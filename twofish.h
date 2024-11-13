#include <stdint.h>

typedef uint8_t     Twofish_Byte;
typedef uint32_t    Twofish_UInt32;

typedef 
    struct 
        {
        Twofish_UInt32 s[4][256];   /* pre-computed S-boxes */
        Twofish_UInt32 K[40];       /* Round key words */
        }
    Twofish_key;

extern void Twofish_initialise();
extern void Twofish_prepare_key( 
                                Twofish_Byte key[],
                                int key_len, 
                                Twofish_key * xkey  
                                );
extern void Twofish_encrypt( 
                            Twofish_key * xkey,
                            Twofish_Byte p[16], 
                            Twofish_Byte c[16]
                            );
extern void Twofish_decrypt( 
                            Twofish_key * xkey,
                            Twofish_Byte c[16], 
                            Twofish_Byte p[16]
                            );
