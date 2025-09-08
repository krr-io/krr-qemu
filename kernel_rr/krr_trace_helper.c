#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include "linux-headers/linux/kernel_rr.h"


// Get the size of each event type
static size_t get_event_size(int type) {
    switch(type) {
        case EVENT_TYPE_INTERRUPT: return sizeof(rr_interrupt);
        case EVENT_TYPE_EXCEPTION: return sizeof(rr_exception);
        case EVENT_TYPE_SYSCALL: return sizeof(rr_syscall);
        case EVENT_TYPE_IO_IN: return sizeof(rr_io_input);
        case EVENT_TYPE_CFU: return sizeof(rr_cfu);
        case EVENT_TYPE_RANDOM: return sizeof(rr_random);
        case EVENT_TYPE_GFU: return sizeof(rr_gfu);
        case EVENT_TYPE_RDTSC: return sizeof(rr_io_input); // Assuming RDTSC stores a single value
        case EVENT_TYPE_DMA_DONE: return sizeof(rr_dma_done); // Assuming simple flag
        case EVENT_TYPE_RDSEED: return sizeof(rr_gfu); // Assuming stores seed value
        case EVENT_TYPE_RELEASE: return sizeof(rr_event_log_guest); // Assuming simple flag
        case EVENT_TYPE_MMIO: return sizeof(rr_io_input);
        case EVENT_TYPE_INST_SYNC: return sizeof(rr_event_log_guest); // Assuming instruction count
        case EVENT_TYPE_PTE: return sizeof(rr_gfu);
        default: return 0;
    }
}

static const char* get_event_type_name(int type) {
    switch(type) {
        case EVENT_TYPE_INTERRUPT: return "INTERRUPT";
        case EVENT_TYPE_EXCEPTION: return "EXCEPTION";
        case EVENT_TYPE_SYSCALL: return "SYSCALL";
        case EVENT_TYPE_IO_IN: return "IO_IN";
        case EVENT_TYPE_CFU: return "CFU";
        case EVENT_TYPE_RANDOM: return "RANDOM";
        case EVENT_TYPE_RDTSC: return "RDTSC";
        case EVENT_TYPE_DMA_DONE: return "DMA_DONE";
        case EVENT_TYPE_GFU: return "GFU";
        case EVENT_TYPE_STRNLEN: return "STRNLEN";
        case EVENT_TYPE_RDSEED: return "RDSEED";
        case EVENT_TYPE_RELEASE: return "RELEASE";
        case EVENT_TYPE_INST_SYNC: return "INST_SYNC";
        case EVENT_TYPE_MMIO: return "MMIO";
        case EVENT_TYPE_PTE: return "PTE";
        default: return "UNKNOWN";
    }
}

static void print_interrupt_event(const rr_interrupt* interrupt) {
    printf("  ID: %d\n", interrupt->id);
    printf("  Vector: %d\n", interrupt->vector);
    printf("  ECX: 0x%lx\n", interrupt->ecx);
    printf("  From: %d\n", interrupt->from);
    printf("  Spin Count: %lu\n", interrupt->spin_count);
    printf("  Instruction Count: %lu\n", interrupt->inst_cnt);
    printf("  RIP: 0x%lx\n", interrupt->rip);
}

static void print_exception_event(const rr_exception* exception) {
    printf("  ID: %d\n", exception->id);
    printf("  Exception Index: %d\n", exception->exception_index);
    printf("  Error Code: %d\n", exception->error_code);
    printf("  CR2: 0x%lx\n", exception->cr2);
    printf("  CR3: 0x%lx\n", exception->cr3);
    printf("  Spin Count: %lu\n", exception->spin_count);
    printf("  Instruction Count: %lu\n", exception->inst_cnt);
}

static void print_syscall_event(const rr_syscall* syscall) {
    printf("  ID: %d\n", syscall->id);
    printf("  Kernel GSBASE: 0x%lx\n", syscall->kernel_gsbase);
    printf("  MSR GSBASE: 0x%lx\n", syscall->msr_gsbase);
    printf("  CR3: 0x%lx\n", syscall->cr3);
    printf("  Spin Count: %lu\n", syscall->spin_count);
}

static void print_io_input_event(const rr_io_input* io_input) {
    printf("  ID: %d\n", io_input->id);
    printf("  Value: 0x%lx\n", io_input->value);
    printf("  Instruction Count: %lu\n", io_input->inst_cnt);
    printf("  RIP: 0x%lx\n", io_input->rip);
}

static void print_cfu_event(const rr_cfu* cfu) {
    printf("  ID: %d\n", cfu->id);
    printf("  Source Address: 0x%lx\n", cfu->src_addr);
    printf("  Dest Address: 0x%lx\n", cfu->dest_addr);
    printf("  Length: %lu\n", cfu->len);
    printf("  RDX: 0x%lx\n", cfu->rdx);
    printf("  Data Pointer: %p\n", cfu->data);
}

static void print_random_event(const rr_random* random) {
    printf("  ID: %d\n", random->id);
    printf("  Buffer: 0x%lx\n", random->buf);
    printf("  Length: %lu\n", random->len);
    printf("  Data (first 16 bytes): ");
    for (int i = 0; i < 16 && i < random->len; i++) {
        printf("%02x ", random->data[i]);
    }
    printf("\n");
}

static void print_gfu_event(const rr_gfu* gfu) {
    printf("  ID: %d\n", gfu->id);
    printf("  Value: 0x%lx\n", gfu->val);
    printf("  Pointer: 0x%lx\n", gfu->ptr);
    printf("  Size: %d\n", gfu->size);
}

static void print_inst_sync_event(const rr_event_log_guest *event) {
    printf("  ID: %d\n", event->id);
    printf("  Instruction Count: %lu\n", event->inst_cnt);
}

static void print_event_details(int event_type, const void* event_data) {
    switch(event_type) {
        case EVENT_TYPE_INTERRUPT:
            print_interrupt_event((rr_interrupt*)event_data);
            break;
        case EVENT_TYPE_EXCEPTION:
            print_exception_event((rr_exception*)event_data);
            break;
        case EVENT_TYPE_SYSCALL:
            print_syscall_event((rr_syscall*)event_data);
            break;
        case EVENT_TYPE_IO_IN:
        case EVENT_TYPE_RDTSC:
        case EVENT_TYPE_MMIO:
            print_io_input_event((rr_io_input*)event_data);
            break;
        case EVENT_TYPE_CFU:
            print_cfu_event((rr_cfu*)event_data);
            break;
        case EVENT_TYPE_RANDOM:
            print_random_event((rr_random*)event_data);
            break;
        case EVENT_TYPE_GFU:
        case EVENT_TYPE_RDSEED:
        case EVENT_TYPE_PTE:
            print_gfu_event((rr_gfu*)event_data);
            break;
        case EVENT_TYPE_INST_SYNC:
        case EVENT_TYPE_RELEASE:
            print_inst_sync_event((rr_event_log_guest*)event_data);
            break;
        default:
            printf("  Event type not fully supported for detailed display\n");
            break;
    }
}

static int matches_criteria(int event_type, const void* event_data, int target_type, int target_id) {
    if (target_type != -1 && event_type != target_type) {
        return 0;
    }
    
    // If target_id is -1, match any ID
    if (target_id == -1) {
        return 1;
    }
    
    // Extract ID based on event type
    int event_id;
    switch(event_type) {
        case EVENT_TYPE_INTERRUPT:
            event_id = ((rr_interrupt*)event_data)->id;
            break;
        case EVENT_TYPE_EXCEPTION:
            event_id = ((rr_exception*)event_data)->id;
            break;
        case EVENT_TYPE_SYSCALL:
            event_id = ((rr_syscall*)event_data)->id;
            break;
        case EVENT_TYPE_IO_IN:
        case EVENT_TYPE_RDTSC:
        case EVENT_TYPE_MMIO:
            event_id = ((rr_io_input*)event_data)->id;
            break;
        case EVENT_TYPE_CFU:
            event_id = ((rr_cfu*)event_data)->id;
            break;
        case EVENT_TYPE_RANDOM:
            event_id = ((rr_random*)event_data)->id;
            break;
        case EVENT_TYPE_GFU:
        case EVENT_TYPE_RDSEED:
        case EVENT_TYPE_PTE:
            event_id = ((rr_gfu*)event_data)->id;
            break;
        case EVENT_TYPE_INST_SYNC:
        case EVENT_TYPE_RELEASE:
            event_id = ((rr_event_log_guest*)event_data)->id;
            break;
        default:
            return 0; // Unsupported event type for ID matching
    }
    
    return event_id == target_id;
}

static int find_and_print_events(void* mapped_mem, int target_type, int target_id, int num_events) {
    rr_event_guest_queue_header* header = (rr_event_guest_queue_header*)mapped_mem;
    int *lock_owner = (int *)(mapped_mem + sizeof(rr_event_guest_queue_header));
    int vcpu_id;
    rr_interrupt *intr_info;

    printf("Queue Header Information:\n");
    printf("  Current Position: %u\n", header->current_pos);
    printf("  Total Position: %u\n", header->total_pos);
    printf("  Header Size: %u\n", header->header_size);
    printf("  Entry Size: %u (note: actual entries have variable sizes)\n", header->entry_size);
    printf("  RR Enabled: %u\n", header->rr_enabled);
    printf("  Current Byte: %lu\n", header->current_byte);
    printf("  Total Size: %lu\n", header->total_size);
    printf("  Rotated Bytes: %lu\n", header->rotated_bytes);
    printf("  Lock Owner %d\n", *lock_owner);
    printf("\n");

    for (vcpu_id = 0; vcpu_id < 2; vcpu_id++) {
        intr_info = (rr_interrupt *)(mapped_mem + sizeof(rr_event_guest_queue_header) + sizeof(unsigned long) + sizeof(rr_interrupt) * vcpu_id);
        printf("  vCPU %d, interrupt instruction %lu, rip=0x%lx, vector %d\n", vcpu_id, intr_info->inst_cnt, intr_info->rip, intr_info->vector);
    }

    if (header->current_byte <= header->header_size) {
        printf("No events in queue.\n");
        return 0;
    }
    
    // Start from the data area (after header)
    char* data_area = (char*)mapped_mem + header->header_size;
    unsigned long data_size = header->current_byte - header->header_size;
    
    // Parse entries from the beginning to build a list
    char* current_pos = data_area;
    char* end_pos = data_area + data_size;
    
    typedef struct {
        int type;
        void* data;
        size_t offset;
    } event_info_t;
    
    event_info_t* events = malloc(header->current_pos * sizeof(event_info_t));
    int event_count = 0;
    
    while (current_pos < end_pos && event_count < header->current_pos) {
        rr_event_entry_header* entry_header = (rr_event_entry_header*)current_pos;
        
        if (current_pos + sizeof(rr_event_entry_header) > end_pos) {
            printf("Warning: Incomplete entry header at end of data\n");
            break;
        }
        
        size_t event_data_size = get_event_size(entry_header->type);
        if (event_data_size == 0) {
            printf("Warning: Unknown event type %d, stopping parsing\n", entry_header->type);
            break;
        }

        if (entry_header->type == EVENT_TYPE_CFU) {
            rr_cfu *cfu = (rr_cfu *)(current_pos + sizeof(rr_event_entry_header));
            event_data_size += cfu->len * sizeof(unsigned char);
        }

        if (current_pos + sizeof(rr_event_entry_header) + event_data_size > end_pos) {
            printf("Warning: Incomplete event data at end of queue\n");
            break;
        }
        
        events[event_count].type = entry_header->type;
        events[event_count].data = current_pos + sizeof(rr_event_entry_header);
        events[event_count].offset = current_pos - data_area;
        event_count++;
        
        current_pos += sizeof(rr_event_entry_header) + event_data_size;
    }
    
    printf("Parsed %d events from queue\n", event_count);
    
    // Collect matching events
    int* matching_indices = malloc(event_count * sizeof(int));
    int match_count = 0;
    
    for (int i = 0; i < event_count; i++) {
        if (matches_criteria(events[i].type, events[i].data, target_type, target_id)) {
            matching_indices[match_count] = i;
            match_count++;
        }
    }
    
    if (match_count == 0) {
        if (target_type == -1 && target_id == -1) {
            printf("No events found in queue\n");
        } else {
            printf("No events found matching criteria (type %d, id %d)\n", target_type, target_id);
        }
        free(events);
        free(matching_indices);
        return 0;
    }
    
    printf("Found %d matching events\n", match_count);
    
    // Determine how many events to print
    int events_to_print = (num_events == -1) ? match_count : 
                         (num_events > match_count) ? match_count : num_events;
    
    // Print the last N matching events
    printf("\n");
    if (num_events == 1) {
        printf("Most Recent Matching Event:\n");
    } else {
        printf("Last %d Matching Events (most recent first):\n", events_to_print);
    }
    printf("=============================\n");
    
    for (int i = 0; i < events_to_print; i++) {
        int event_idx = matching_indices[match_count - 1 - i]; // Start from most recent
        int event_type = events[event_idx].type;
        void* event_data = events[event_idx].data;
        
        if (events_to_print > 1) {
            printf("\nEvent #%d (Index %d):\n", i + 1, event_idx);
        }
        printf("Event Type: %s (%d)\n", get_event_type_name(event_type), event_type);
        print_event_details(event_type, event_data);
        
        if (events_to_print > 1 && i < events_to_print - 1) {
            printf("-----------------------------\n");
        }
    }
    
    free(events);
    free(matching_indices);
    return events_to_print;
}

static void print_usage(const char* program_name) {
    printf("Usage: %s <event_type> <event_id> [num_events]\n", program_name);
    printf("\nArguments:\n");
    printf("  event_type  : Event type to search for (-1 for any type)\n");
    printf("  event_id    : Event ID to search for (-1 for any ID)\n");
    printf("  num_events  : Number of last events to print (default: 1, -1 for all)\n");
    printf("\nEvent types:\n");
    printf("  -1 - ANY TYPE\n");
    printf("   0 - INTERRUPT\n");
    printf("   1 - EXCEPTION\n");
    printf("   2 - SYSCALL\n");
    printf("   3 - IO_IN\n");
    printf("   4 - CFU\n");
    printf("   5 - RANDOM\n");
    printf("   6 - RDTSC\n");
    printf("   7 - DMA_DONE\n");
    printf("   8 - GFU\n");
    printf("   9 - STRNLEN\n");
    printf("  10 - RDSEED\n");
    printf("  11 - RELEASE\n");
    printf("  12 - INST_SYNC\n");
    printf("  13 - MMIO\n");
    printf("  14 - PTE\n");
    printf("\nExamples:\n");
    printf("  %s 0 123        # Find most recent INTERRUPT with ID 123\n", program_name);
    printf("  %s 0 123 5      # Find last 5 INTERRUPT events with ID 123\n", program_name);
    printf("  %s -1 -1 10     # Find last 10 events of any type and ID\n", program_name);
    printf("  %s 2 -1 -1      # Find all SYSCALL events (any ID)\n", program_name);
}

int main(int argc, char* argv[]) {
    if (argc > 4) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Default values: match any type, any ID, show 1 event
    int target_type = -1;
    int target_id = -1;
    int num_events = 1;
    
    // Parse arguments if provided
    if (argc >= 2) {
        target_type = atoi(argv[1]);
    }
    if (argc >= 3) {
        target_id = atoi(argv[2]);
    }
    if (argc >= 4) {
        num_events = atoi(argv[3]);
    }
    
    // Validate arguments
    if (target_type < -1 || target_type > 14) {
        printf("Error: Invalid event type %d. Use -1 for any type or 0-14 for specific types.\n", target_type);
        print_usage(argv[0]);
        return 1;
    }
    
    // Open the memory-mapped file
    int fd = open("/dev/shm/ivshmem", O_RDONLY);
    if (fd == -1) {
        perror("Failed to open /dev/shm/ivshmem");
        return 1;
    }
    
    // Get file size
    struct stat st;
    if (fstat(fd, &st) == -1) {
        perror("Failed to get file size");
        close(fd);
        return 1;
    }
    
    // Map the file into memory
    void* mapped_mem = mmap(NULL, st.st_size, PROT_READ, MAP_SHARED, fd, 0);
    if (mapped_mem == MAP_FAILED) {
        perror("Failed to map memory");
        close(fd);
        return 1;
    }
    
    printf("Successfully mapped %ld bytes from /dev/shm/ivshmem\n", st.st_size);
    
    // Print search criteria
    if (target_type == -1 && target_id == -1) {
        if (num_events == -1) {
            printf("Searching for all events\n\n");
        } else {
            printf("Searching for last %d events of any type\n\n", num_events);
        }
    } else if (target_type == -1) {
        if (num_events == -1) {
            printf("Searching for all events with ID %d\n\n", target_id);
        } else {
            printf("Searching for last %d events with ID %d\n\n", num_events, target_id);
        }
    } else if (target_id == -1) {
        if (num_events == -1) {
            printf("Searching for all %s events\n\n", get_event_type_name(target_type));
        } else {
            printf("Searching for last %d %s events\n\n", num_events, get_event_type_name(target_type));
        }
    } else {
        if (num_events == -1) {
            printf("Searching for all %s events with ID %d\n\n", get_event_type_name(target_type), target_id);
        } else {
            printf("Searching for last %d %s events with ID %d\n\n", num_events, get_event_type_name(target_type), target_id);
        }
    }
    
    // Find and display events
    int events_found = find_and_print_events(mapped_mem, target_type, target_id, num_events);
    
    // Cleanup
    munmap(mapped_mem, st.st_size);
    close(fd);
    
    return events_found > 0 ? 0 : 1;
}
