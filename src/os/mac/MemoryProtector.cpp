#include <libhat/defines.hpp>
#ifdef LIBHAT_MAC

#include <libhat/memory_protector.hpp>
#include <libhat/system.hpp>
#include "../../Utils.hpp"

#include <sys/mman.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>

#include <optional>

namespace hat {

    static std::optional<vm_prot_t> get_page_prot(const uintptr_t address) {
        std::optional<vm_prot_t> prot;
        
        mach_port_t task = mach_task_self();
        vm_address_t targetAddr = static_cast<vm_address_t>(address);
        vm_size_t regionSize = 0;
        struct vm_region_basic_info_64 info;
        mach_msg_type_number_t infoCount = VM_REGION_BASIC_INFO_COUNT_64;
        mach_port_t objectName;

        kern_return_t kr = vm_region_64(
            task,
            &targetAddr,
            &regionSize,
            VM_REGION_BASIC_INFO_64,
            reinterpret_cast<vm_region_info_t>(&info),
            &infoCount,
            &objectName
        );

        if (kr == KERN_SUCCESS) {
            prot = info.protection;
        }

        return prot;
    }

    static vm_prot_t to_system_prot(const protection flags) {
        vm_prot_t prot = 0;
        if (static_cast<bool>(flags & protection::Read)) prot |= VM_PROT_READ;
        if (static_cast<bool>(flags & protection::Write)) prot |= VM_PROT_WRITE;
        if (static_cast<bool>(flags & protection::Execute)) prot |= VM_PROT_EXECUTE;
        return prot;
    }

    memory_protector::memory_protector(const uintptr_t address, const size_t size, const protection flags) : address(address), size(size) {
        const auto oldProt = get_page_prot(address);
        if (!oldProt) {
            return; // Failure indicated via is_set()
        }

        this->oldProtection = static_cast<uint32_t>(*oldProt);
        this->set = KERN_SUCCESS == vm_protect(
            mach_task_self(),
            address,
            size,
            FALSE,
            to_system_prot(flags)
        );
    }

    void memory_protector::restore() {
        vm_protect(
            mach_task_self(),
            static_cast<vm_address_t>(address),
            size,
            FALSE,
            static_cast<vm_prot_t>(oldProtection)
        );
    }
}
#endif
