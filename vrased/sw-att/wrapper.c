#include <string.h>

#define SIG_TEMP     (0x6000)

// TODO: SIG_RESP_ADDR should be modified
#define SIG_RESP_ADDR     (0x03D0)

#define KEY_ADDR          (0x6A00)

#define ATTEST_DATA_ADDR  (0xE000)
#define ATTEST_SIZE       (0x2000)

#define SCACHE_FLAG       (0xFFDF)
#define SCACHE_IVT        (0xFFE0)

#define EP_START          (0x0140)
#define EP_END            (0x0142)
#define B_EP_START        (0xFFDA)
#define B_EP_END          (0xFFDC)

#define SIZE_SW_SIZE      (2)
#define SIZE_VER_INFO     (2)
#define SIZE_NONCE        (32)
#define SIZE_IVT          (32)
#define SIZE_SIGNATURE    (32)

#define ER_FIRST_SW_START   (0xE000)
#define ER_SECOND_SW_START  (0xF000)
#define OFFSET_SW_SIZE    (0)
#define OFFSET_VER_INFO   (OFFSET_SW_SIZE + SIZE_SW_SIZE)
#define OFFSET_NONCE      (OFFSET_VER_INFO + SIZE_VER_INFO)

#define SIZE_HEADER       (OFFSET_NONCE + SIZE_NONCE)
#define SIZE_KEY          (32)


/* TODO: Work around for the version information of existing software */
#define EXISTING_SW_VERSION  (0xFFD8)

extern void
hmac(
  uint8_t *mac,
  uint8_t *key,
  uint32_t keylen,
  uint8_t *data,
  uint32_t datalen
);

void my_memset(uint8_t* ptr, int len, uint8_t val) {
  int i=0;
  for(i=0; i<len; i++) ptr[i] = val;
}

void my_memcpy(uint8_t* dst, uint8_t* src, int size) {
  int i=0;
  for(i=0; i<size; i++) dst[i] = src[i];
}

// CASU function signatures
void CASU_entry();
void CASU_update_authenticate();
void CASU_update_install();
void CASU_jump_to_ER_routine();
void CASU_exit();
int secure_memcmp(const uint8_t* s1, const uint8_t* s2, int size);

/* [CASU-SW] Entry function */
__attribute__ ((section (".do_mac.call"))) void CASU_entry() {
    // Set the Stack Pointer to Secure Stack at entry
    __asm__ volatile("mov    #0x1000,     r1" "\n\t");
    
    // Check whether SCACHE_FLAG is 1. If yes, jump to CASU_update_install().
    if (*(uint8_t*)SCACHE_FLAG != 0) {
      CASU_update_install();
    }

    // Otherwise, check whether r4 is 0. If yes, jump to CASU_jump_to_ER_routine_init().
    __asm__ volatile("tst.b    r4" "\n\t");
    __asm__ volatile("jz    CASU_jump_to_ER_routine_init" "\n\t");

    // Otherwise, jump to CASU_update_authenticate().
    __asm__ volatile("jmp    CASU_update_authenticate" "\n\t");

}


__attribute__ ((section (".do_mac.body"))) void CASU_update_authenticate() {
    uint8_t key[SIZE_KEY] = {0};

    memcpy(key, (uint8_t*)KEY_ADDR, SIZE_KEY);

    /* Work around for version number of existing software */
    // Check if the version number is greater than the previous one.
    if ( *(uint16_t*)((uint8_t*)B_EP_START+OFFSET_VER_INFO) <= *(uint16_t*)((uint8_t*)EXISTING_SW_VERSION) ) {
      CASU_jump_to_ER_routine_init();
    }

    // Compute HMAC on the bEP.
    uint8_t signature[SIZE_SIGNATURE] = {0};
    uint8_t *bEP_min = (uint8_t*)(*((uint16_t*)B_EP_START));
    uint16_t bEP_size = ((*(uint16_t*)B_EP_END) - (*(uint16_t*)B_EP_START)) + 2;

    hmac((uint8_t *)signature, (uint8_t *)key, (uint32_t)SIZE_KEY, (uint8_t *)bEP_min, (uint32_t)bEP_size);

    // Check if signature == SIG_RESP_ADDR. If yes, jump to CASU_update_install()
    if (secure_memcmp(signature, (uint8_t *)SIG_RESP_ADDR, sizeof(signature)) == 0) {
      CASU_update_install();
    }

    // Otherwise, jump to CASU_jump_to_ER_routine_init()
    CASU_jump_to_ER_routine_init();
}

__attribute__ ((section (".do_mac.body"))) void CASU_update_install() {

    // Set SCACHE_FLAG to 1
    if (*(uint8_t*)SCACHE_FLAG == 0) {
        *(uint8_t*)SCACHE_FLAG = 1;
    }

    // Check whether EP_START == B_EP_START, if not, copy B_EP_START to EP_START
    if (*(uint16_t*)EP_START != (*(uint16_t*)B_EP_START)) {
      *(uint16_t*)EP_START = *(uint16_t*)B_EP_START;
      *(uint16_t*)EP_END = *(uint16_t*)B_EP_END;
    }

    // Copy new IVT (from software at B_EP_START) to SCACHE_IVT and make sure Reset handler is 0xA000
    memcpy((uint8_t*)SCACHE_IVT, (uint8_t*)(*(uint16_t*)B_EP_END) + 2 - SIZE_IVT, SIZE_IVT);

    // Compute response and store to SIG_RESP_ADDR
    uint8_t key[SIZE_KEY] = {0};
    memcpy(key, (uint8_t*)KEY_ADDR, SIZE_KEY);
    uint8_t response_body[SIZE_VER_INFO + SIZE_NONCE] = {0};
    *(uint16_t*)response_body = *(uint16_t*)((uint8_t*)(*(uint16_t*)B_EP_START) + OFFSET_VER_INFO);
    memcpy(response_body + SIZE_VER_INFO, (uint8_t*)(*(uint16_t*)B_EP_START) + OFFSET_NONCE, SIZE_NONCE);
    hmac((uint8_t*)SIG_RESP_ADDR, (uint8_t*) key, (uint32_t) SIZE_KEY, response_body, (uint32_t)(SIZE_VER_INFO + SIZE_NONCE));

    // Set SCACHE_FLAG to 0
    *(uint8_t *)SCACHE_FLAG = 0;

    CASU_jump_to_ER_routine();
}

__attribute__ ((section (".do_mac.body"))) void CASU_jump_to_ER_routine_init() {

    // Read the ER start address from EP_START and store in r5
    __asm__ volatile("mov    #0x0140,   r5" "\n\t");
    __asm__ volatile("mov    @(r5),     r5" "\n\t");

    // Set the Stack Pointer to ER Stack before leaving CASU
    __asm__ volatile("mov    #0x6200,     r1" "\n\t");
    __asm__ volatile("clr    r3" "\n\t");
    __asm__ volatile("clr    r4" "\n\t");
    __asm__ volatile("clr    r6" "\n\t");
    __asm__ volatile("clr    r7" "\n\t");
    __asm__ volatile("clr    r8" "\n\t");
    __asm__ volatile("clr    r9" "\n\t");
    __asm__ volatile("clr    r10" "\n\t");
    __asm__ volatile("clr    r11" "\n\t");
    __asm__ volatile("clr    r12" "\n\t");
    __asm__ volatile("clr    r13" "\n\t");
    __asm__ volatile("clr    r14" "\n\t");
    __asm__ volatile("clr    r15" "\n\t");

    // Jump to CASU_exit
    __asm__ volatile( "br      #__mac_leave" "\n\t");
}

__attribute__ ((section (".do_mac.body"))) void CASU_jump_to_ER_routine() {

    // Read the ER start address from EP_START and store in r5
    __asm__ volatile("mov    #0x0140,   r5" "\n\t");
    __asm__ volatile("mov    @(r5),     r5" "\n\t");
    // Jump to the starting of the software. The header size is 36
    __asm__ volatile("add    #36,     r5" "\n\t");

    // Set the Stack Pointer to ER Stack before leaving CASU
    __asm__ volatile("mov    #0x6200,     r1" "\n\t");
    __asm__ volatile("clr    r3" "\n\t");
    __asm__ volatile("clr    r4" "\n\t");
    __asm__ volatile("clr    r6" "\n\t");
    __asm__ volatile("clr    r7" "\n\t");
    __asm__ volatile("clr    r8" "\n\t");
    __asm__ volatile("clr    r9" "\n\t");
    __asm__ volatile("clr    r10" "\n\t");
    __asm__ volatile("clr    r11" "\n\t");
    __asm__ volatile("clr    r12" "\n\t");
    __asm__ volatile("clr    r13" "\n\t");
    __asm__ volatile("clr    r14" "\n\t");
    __asm__ volatile("clr    r15" "\n\t");

    // Jump to CASU_exit
    __asm__ volatile( "br      #__mac_leave" "\n\t");
}


__attribute__ ((section (".do_mac.body"))) int secure_memcmp(const uint8_t* s1, const uint8_t* s2, int size) {
    int res = 0;
    int first = 1;
    for(int i = 0; i < size; i++) {
      if (first == 1 && s1[i] > s2[i]) {
        res = 1;
        first = 0;
      }
      else if (first == 1 && s1[i] < s2[i]) {
        res = -1;
        first = 0;
      }
    }
    return res;
}

/* [CASU-SW] Exit function */
__attribute__ ((section (".do_mac.leave"))) __attribute__((naked)) void CASU_exit() {
    __asm__ volatile("br   r5" "\n\t");
}

/* Update routine in SW */
void CASU_secure_update (uint8_t *update_code, uint8_t *signature) {
    
    uint16_t new_ep_start = 0;
    uint16_t new_ep_end = 0;
    uint16_t update_code_size = *(uint16_t*)(update_code+OFFSET_SW_SIZE);
    // Copy input signature to SIG_RESP_ADDR:
    my_memcpy ((uint8_t*)SIG_RESP_ADDR, signature, SIZE_SIGNATURE);

    // Check EP_START and decide where to write the update_code.
    if ( (*(uint16_t*)EP_START >= ER_FIRST_SW_START) && (*(uint16_t*)EP_START < ER_SECOND_SW_START) ) {
      new_ep_start = ER_SECOND_SW_START;
    } else {
      new_ep_start = ER_FIRST_SW_START;
    }
    new_ep_end = new_ep_start + update_code_size - 2;

    // Write the update_code at that location and update B_EP_START.
    my_memcpy((uint8_t*)new_ep_start, update_code, update_code_size);
    *(uint16_t*)B_EP_START = new_ep_start;
    *(uint16_t*)B_EP_END = new_ep_end;

    // Set r4 as 1
    __asm__ volatile("mov    #1,  r4" "\n\t");

    //Disable interrupts:
    __dint();

    // Call CASU:
    CASU_entry();
}
