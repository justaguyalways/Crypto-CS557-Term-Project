#include <string.h>     /* for memset(), memcpy(), and memcmp() */
#include "twofish.h"

#define Twofish_fatal( msg )      {for(;;);}
#define UINT32_MASK    ( (((UInt32)2)<<31) - 1 )
#define ROL32( x, n )  ( (x)<<(n) | ((x) & UINT32_MASK) >> (32-(n)) )
#define ROR32( x, n )  ROL32( (x), 32-(n) )
#define LARGE_Q_TABLE   0    /* default = 0 */
#define SELECT_BYTE_FROM_UINT32_IN_MEMORY    0    /* default = 0 */
#define CONVERT_USING_CASTS    0    /* default = 0 */
#define CPU_IS_BIG_ENDIAN    0
#define BSWAP(x) ((ROL32((x),8) & 0x00ff00ff) | (ROR32((x),8) & 0xff00ff00))

/* A Byte must be an unsigned integer, 8 bits long. */
typedef Twofish_Byte    Byte;
/* A UInt32 must be an unsigned integer at least 32 bits long. */
typedef Twofish_UInt32  UInt32;

#if CPU_IS_BIG_ENDIAN
#define ENDIAN_CONVERT(x)    BSWAP(x)
#else
#define ENDIAN_CONVERT(x)    (x)
#endif

#if CPU_IS_BIG_ENDIAN
#define BYTE_OFFSET( n )  (sizeof(UInt32) - 1 - (n) )
#else
#define BYTE_OFFSET( n )  (n)
#endif

/*
 * Macro to get Byte no. b from UInt32 value X.
 * We use two different definition, depending on the settings.
 */
#if SELECT_BYTE_FROM_UINT32_IN_MEMORY
    /* Pick the byte from the memory in which X is stored. */
#define SELECT_BYTE( X, b ) (((Byte *)(&(X)))[BYTE_OFFSET(b)])
#else
    /* Portable solution: Pick the byte directly from the X value. */
#define SELECT_BYTE( X, b ) (((X) >> 8*(b)) & 0xff)
#endif


/* Some shorthands because we use byte selection in large formulae. */
#define b0(X)   SELECT_BYTE((X),0)
#define b1(X)   SELECT_BYTE((X),1)
#define b2(X)   SELECT_BYTE((X),2)
#define b3(X)   SELECT_BYTE((X),3)


#if CONVERT_USING_CASTS

    /* Get UInt32 from four bytes pointed to by p. */
#define GET32( p )    ENDIAN_CONVERT( *((UInt32 *)(p)) )
    /* Put UInt32 into four bytes pointed to by p */
#define PUT32( v, p ) *((UInt32 *)(p)) = ENDIAN_CONVERT(v)

#else

    /* Get UInt32 from four bytes pointed to by p. */
#define GET32( p ) \
    ( \
      (UInt32)((p)[0])    \
    | (UInt32)((p)[1])<< 8\
    | (UInt32)((p)[2])<<16\
    | (UInt32)((p)[3])<<24\
    )
    /* Put UInt32 into four bytes pointed to by p */
#define PUT32( v, p ) \
    (p)[0] = (Byte)(((v)      ) & 0xff);\
    (p)[1] = (Byte)(((v) >>  8) & 0xff);\
    (p)[2] = (Byte)(((v) >> 16) & 0xff);\
    (p)[3] = (Byte)(((v) >> 24) & 0xff)

#endif

static void test_platform()
    {
    /* Buffer with test values. */
    Byte buf[] = {0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0};
    UInt32 C;
    UInt32 x,y;
    int i;


    if( ((UInt32) ((UInt32)1 << 31) == 0) || ((UInt32)-1 < 0) ) 
        {
        Twofish_fatal( "Twofish code: Twofish_UInt32 type not suitable" );
        }
    if( (sizeof( Byte ) != 1) || ((Byte)-1 < 0) ) 
        {
        Twofish_fatal( "Twofish code: Twofish_Byte type not suitable" );
        }


    if( GET32( buf ) != 0x78563412UL || GET32(buf+1) != 0x9a785634UL 
        || GET32( buf+2 ) != 0xbc9a7856UL || GET32(buf+3) != 0xdebc9a78UL )
        {
        Twofish_fatal( "Twofish code: GET32 not implemented properly" );
        }

    /* 
     * We can now use GET32 to test PUT32.
     * We don't test the shifted versions. If GET32 can do that then
     * so should PUT32.
     */
    C = GET32( buf );
    PUT32( 3*C, buf );
    if( GET32( buf ) != 0x69029c36UL )
        {
        Twofish_fatal( "Twofish code: PUT32 not implemented properly" );
        }


    /* Test ROL and ROR */
    for( i=1; i<32; i++ ) 
        {
        /* Just a simple test. */
        x = ROR32( C, i );
        y = ROL32( C, i );
        x ^= (C>>i) ^ (C<<(32-i));
        y ^= (C<<i) ^ (C>>(32-i));
        x |= y;
        /* 
         * Now all we check is that x is zero in the least significant
         * 32 bits. Using the UL suffix is safe here, as it doesn't matter
         * if we get a larger type.
         */
        if( (x & 0xffffffffUL) != 0 )
            {
            Twofish_fatal( "Twofish ROL or ROR not properly defined." );
            }
        }

    /* Test the BSWAP macro */
    if( (BSWAP(C)) != 0x12345678UL )
        {
        /*
         * The BSWAP macro should always work, even if you are not using it.
         * A smart optimising compiler will just remove this entire test.
         */
        Twofish_fatal( "BSWAP not properly defined." );
        }

    /* And we can test the b<i> macros which use SELECT_BYTE. */
    if( (b0(C)!=0x12) || (b1(C) != 0x34) || (b2(C) != 0x56) || (b3(C) != 0x78) )
        {
        /*
         * There are many reasons why this could fail.
         * Most likely is that CPU_IS_BIG_ENDIAN has the wrong value. 
         */
        Twofish_fatal( "Twofish code: SELECT_BYTE not implemented properly" );
        }
    }


/*
 * Perform a single self test on a (plaintext,ciphertext,key) triple.
 * Arguments:
 *  key     array of key bytes
 *  key_len length of key in bytes
 *  p       plaintext
 *  c       ciphertext
 */
static void test_vector( Byte key[], int key_len, Byte p[16], Byte c[16] )
    {
    Byte tmp[16];               /* scratch pad. */
    Twofish_key xkey;           /* The expanded key */
    int i;


    /* Prepare the key */
    Twofish_prepare_key( key, key_len, &xkey );

    for( i=0; i<2; i++ ) 
        {
        /* Encrypt and test */
        Twofish_encrypt( &xkey, p, tmp );
        if( memcmp( c, tmp, 16 ) != 0 ) 
            {
            Twofish_fatal( "Twofish encryption failure" );
            }

        /* Decrypt and test */
        Twofish_decrypt( &xkey, c, tmp );
        if( memcmp( p, tmp, 16 ) != 0 ) 
            {
            Twofish_fatal( "Twofish decryption failure" );
            }
        }

    }


static void test_vectors()
    {

    /* 128-bit test is the I=3 case of section B.2 of the Twofish book. */
    static Byte k128[] = {
        0x9F, 0x58, 0x9F, 0x5C, 0xF6, 0x12, 0x2C, 0x32, 
        0xB6, 0xBF, 0xEC, 0x2F, 0x2A, 0xE8, 0xC3, 0x5A,
        };
    static Byte p128[] = {
        0xD4, 0x91, 0xDB, 0x16, 0xE7, 0xB1, 0xC3, 0x9E, 
        0x86, 0xCB, 0x08, 0x6B, 0x78, 0x9F, 0x54, 0x19
        };
    static Byte c128[] = {
        0x01, 0x9F, 0x98, 0x09, 0xDE, 0x17, 0x11, 0x85, 
        0x8F, 0xAA, 0xC3, 0xA3, 0xBA, 0x20, 0xFB, 0xC3
        };

    /* 192-bit test is the I=4 case of section B.2 of the Twofish book. */
    static Byte k192[] = {
        0x88, 0xB2, 0xB2, 0x70, 0x6B, 0x10, 0x5E, 0x36, 
        0xB4, 0x46, 0xBB, 0x6D, 0x73, 0x1A, 0x1E, 0x88, 
        0xEF, 0xA7, 0x1F, 0x78, 0x89, 0x65, 0xBD, 0x44
        };
    static Byte p192[] = {
        0x39, 0xDA, 0x69, 0xD6, 0xBA, 0x49, 0x97, 0xD5,
        0x85, 0xB6, 0xDC, 0x07, 0x3C, 0xA3, 0x41, 0xB2
        };
    static Byte c192[] = {
        0x18, 0x2B, 0x02, 0xD8, 0x14, 0x97, 0xEA, 0x45,
        0xF9, 0xDA, 0xAC, 0xDC, 0x29, 0x19, 0x3A, 0x65
        };

    /* 256-bit test is the I=4 case of section B.2 of the Twofish book. */
    static Byte k256[] = {
        0xD4, 0x3B, 0xB7, 0x55, 0x6E, 0xA3, 0x2E, 0x46, 
        0xF2, 0xA2, 0x82, 0xB7, 0xD4, 0x5B, 0x4E, 0x0D,
        0x57, 0xFF, 0x73, 0x9D, 0x4D, 0xC9, 0x2C, 0x1B,
        0xD7, 0xFC, 0x01, 0x70, 0x0C, 0xC8, 0x21, 0x6F
        };
    static Byte p256[] = {
        0x90, 0xAF, 0xE9, 0x1B, 0xB2, 0x88, 0x54, 0x4F,
        0x2C, 0x32, 0xDC, 0x23, 0x9B, 0x26, 0x35, 0xE6
        };
    static Byte c256[] = {
        0x6C, 0xB4, 0x56, 0x1C, 0x40, 0xBF, 0x0A, 0x97,
        0x05, 0x93, 0x1C, 0xB6, 0xD4, 0x08, 0xE7, 0xFA
        };

    /* Run the actual tests. */
    test_vector( k128, 16, p128, c128 );
    test_vector( k192, 24, p192, c192 );
    test_vector( k256, 32, p256, c256 );
    }   


static void test_sequence( int key_len, Byte final_value[] )
    {
    Byte buf[ (50+3)*16 ];      /* Buffer to hold our computation values. */
    Byte tmp[16];               /* Temp for testing the decryption. */
    Twofish_key xkey;           /* The expanded key */
    int i;                      
    Byte * p;

    /* Wipe the buffer */
    memset( buf, 0, sizeof( buf ) );

    /*
     * Because the recurrence relation is done in an inconvenient manner
     * we end up looping backwards over the buffer.
     */

    /* Pointer in buffer points to current plaintext. */
    p = &buf[50*16];
    for( i=1; i<50; i++ )
        {
        /* 
         * Prepare a key.
         * This automatically checks that key_len is valid.
         */
        Twofish_prepare_key( p+16, key_len, &xkey );

        /* Compute the next 16 bytes in the buffer */
        Twofish_encrypt( &xkey, p, p-16 );

        /* Check that the decryption is correct. */
        Twofish_decrypt( &xkey, p-16, tmp );
        if( memcmp( tmp, p, 16 ) != 0 )
            {
            Twofish_fatal( "Twofish decryption failure in sequence" );
            }
        /* Move on to next 16 bytes in the buffer. */
        p -= 16;
        }

    /* And check the final value. */
    if( memcmp( p, final_value, 16 ) != 0 ) 
        {
        Twofish_fatal( "Twofish encryption failure in sequence" );
        }

    /* None of the data was secret, so there is no need to wipe anything. */
    }


static void test_sequences()
    {
    static Byte r128[] = {
        0x5D, 0x9D, 0x4E, 0xEF, 0xFA, 0x91, 0x51, 0x57,
        0x55, 0x24, 0xF1, 0x15, 0x81, 0x5A, 0x12, 0xE0
        };
    static Byte r192[] = {
        0xE7, 0x54, 0x49, 0x21, 0x2B, 0xEE, 0xF9, 0xF4,
        0xA3, 0x90, 0xBD, 0x86, 0x0A, 0x64, 0x09, 0x41
        };
    static Byte r256[] = {
        0x37, 0xFE, 0x26, 0xFF, 0x1C, 0xF6, 0x61, 0x75,
        0xF5, 0xDD, 0xF4, 0xC3, 0x3B, 0x97, 0xA2, 0x05
        };

    /* Run the three sequence test vectors */
    test_sequence( 16, r128 );
    test_sequence( 24, r192 );
    test_sequence( 32, r256 );
    }


static void test_odd_sized_keys()
    {
    Byte buf[32];
    Twofish_key xkey;
    Twofish_key xkey_two;
    int i;

    memset( buf, 0, sizeof( buf ) );
    Twofish_prepare_key( buf, 16, &xkey );

    /* Fill buffer with pseudo-random data derived from two encryptions */
    Twofish_encrypt( &xkey, buf, buf );
    Twofish_encrypt( &xkey, buf, buf+16 );

    /* Create all possible shorter keys that are prefixes of the buffer. */
    for( i=31; i>=0; i-- )
        {
        /* Set a byte to zero. This is the new padding byte */
        buf[i] = 0;

        /* Expand the key with only i bytes of length */
        Twofish_prepare_key( buf, i, &xkey );

        /* Expand the corresponding padded key of regular length */
        Twofish_prepare_key( buf, i<=16 ? 16 : i<= 24 ? 24 : 32, &xkey_two );

        /* Compare the two */
        if( memcmp( &xkey, &xkey_two, sizeof( xkey ) ) != 0 )
            {
            Twofish_fatal( "Odd sized keys do not expand properly" );
            }
        }

    /* None of the key values are secret, so we don't need to wipe them. */
    }

static void self_test()
    {
    /* The three test vectors form an absolute minimal test set. */
    test_vectors();

    /* 
     * If at all possible you should run these tests too. They take
     * more time, but provide a more thorough coverage.
     */
    test_sequences();

    /* Test the odd-sized keys. */
    test_odd_sized_keys();
    }

static Byte t_table[2][4][16] = {
    {
        {0x8,0x1,0x7,0xD,0x6,0xF,0x3,0x2,0x0,0xB,0x5,0x9,0xE,0xC,0xA,0x4},
        {0xE,0xC,0xB,0x8,0x1,0x2,0x3,0x5,0xF,0x4,0xA,0x6,0x7,0x0,0x9,0xD},
        {0xB,0xA,0x5,0xE,0x6,0xD,0x9,0x0,0xC,0x8,0xF,0x3,0x2,0x4,0x7,0x1},
        {0xD,0x7,0xF,0x4,0x1,0x2,0x6,0xE,0x9,0xB,0x3,0x0,0x8,0x5,0xC,0xA}
    },
    {
        {0x2,0x8,0xB,0xD,0xF,0x7,0x6,0xE,0x3,0x1,0x9,0x4,0x0,0xA,0xC,0x5},
        {0x1,0xE,0x2,0xB,0x4,0xC,0x3,0x7,0x6,0xD,0xA,0x5,0xF,0x9,0x0,0x8},
        {0x4,0xC,0x7,0x5,0x1,0x6,0x9,0xA,0x0,0xE,0xD,0x8,0x2,0xB,0x3,0xF},
        {0xB,0x9,0x5,0x1,0xC,0x3,0xD,0xE,0x6,0x4,0x7,0xF,0x2,0x0,0x8,0xA}
    }
};


/* A 1-bit rotation of 4-bit values. Input must be in range 0..15 */
#define ROR4BY1( x ) (((x)>>1) | (((x)<<3) & 0x8) )

/*
 * The q-boxes are only used during the key schedule computations. 
 * These are 8->8 bit lookup tables. Some CPUs prefer to have 8->32 bit 
 * lookup tables as it is faster to load a 32-bit value than to load an 
 * 8-bit value and zero the rest of the register.
 * The LARGE_Q_TABLE switch allows you to choose 32-bit entries in 
 * the q-tables. Here we just define the Qtype which is used to store 
 * the entries of the q-tables.
 */
#if LARGE_Q_TABLE
typedef UInt32      Qtype;
#else
typedef Byte        Qtype;
#endif

/* 
 * The actual q-box tables. 
 * There are two q-boxes, each having 256 entries.
 */
static Qtype q_table[2][256];


/*
 * Now the function that converts a single t-table into a q-table.
 *
 * Arguments:
 * t[4][16] : four 4->4bit lookup tables that define the q-box
 * q[256]   : output parameter: the resulting q-box as a lookup table.
 */
static void make_q_table( Byte t[4][16], Qtype q[256] )
    {
    int ae,be,ao,bo;        /* Some temporaries. */
    int i;
    /* Loop over all input values and compute the q-box result. */
    for( i=0; i<256; i++ ) {
        /* 
         * This is straight from the Twofish specifications. 
         * 
         * The ae variable is used for the a_i values from the specs
         * with even i, and ao for the odd i's. Similarly for the b's.
         */
        ae = i>>4; be = i&0xf;
        ao = ae ^ be; bo = ae ^ ROR4BY1(be) ^ ((ae<<3)&8);
        ae = t[0][ao]; be = t[1][bo];
        ao = ae ^ be; bo = ae ^ ROR4BY1(be) ^ ((ae<<3)&8);
        ae = t[2][ao]; be = t[3][bo];

        /* Store the result in the q-box table, the cast avoids a warning. */
        q[i] = (Qtype) ((be<<4) | ae);
        }
    }


/* 
 * Initialise both q-box tables. 
 */
static void initialise_q_boxes() {
    /* Initialise each of the q-boxes using the t-tables */
    make_q_table( t_table[0], q_table[0] );
    make_q_table( t_table[1], q_table[1] );
    }


/*
 * The MDS matrix multiplication operates in the field
 * GF(2)[x]/p(x) with p(x)=x^8+x^6+x^5+x^3+1.
 * If you don't understand this, read a book on finite fields. You cannot
 * follow the finite-field computations without some background.
 * 
 * In this field, multiplication by x is easy: shift left one bit 
 * and if bit 8 is set then xor the result with 0x169. 
 *
 * The MDS coefficients use a multiplication by 1/x,
 * or rather a division by x. This is easy too: first make the
 * value 'even' (i.e. bit 0 is zero) by xorring with 0x169 if necessary, 
 * and then shift right one position. 
 * Even easier: shift right and xor with 0xb4 if the lsbit was set.
 *
 * The MDS coefficients are 1, EF, and 5B, and we use the fact that
 *   EF = 1 + 1/x + 1/x^2
 *   5B = 1       + 1/x^2
 * in this field. This makes multiplication by EF and 5B relatively easy.
 *
 * This property is no accident, the MDS matrix was designed to allow
 * this implementation technique to be used.
 *
 * We have four MDS tables, each mapping 8 bits to 32 bits.
 * Each table performs one column of the matrix multiplication. 
 * As the MDS is always preceded by q-boxes, each of these tables
 * also implements the q-box just previous to that column.
 */

/* The actual MDS tables. */
static UInt32 MDS_table[4][256];

/* A small table to get easy conditional access to the 0xb4 constant. */
static UInt32 mds_poly_divx_const[] = {0,0xb4};

/* Function to initialise the MDS tables. */
static void initialise_mds_tables()
    {
    int i;
    UInt32 q,qef,q5b;       /* Temporary variables. */

    /* Loop over all 8-bit input values */
    for( i=0; i<256; i++ ) 
        {
        /* 
         * To save some work during the key expansion we include the last
         * of the q-box layers from the h() function in these MDS tables.
         */

        /* We first do the inputs that are mapped through the q0 table. */
        q = q_table[0][i];
        /*
         * Here we divide by x, note the table to get 0xb4 only if the 
         * lsbit is set. 
         * This sets qef = (1/x)*q in the finite field
         */
        qef = (q >> 1) ^ mds_poly_divx_const[ q & 1 ];
        /*
         * Divide by x again, and add q to get (1+1/x^2)*q. 
         * Note that (1+1/x^2) =  5B in the field, and addition in the field
         * is exclusive or on the bits.
         */
        q5b = (qef >> 1) ^ mds_poly_divx_const[ qef & 1 ] ^ q;
        /* 
         * Add q5b to qef to set qef = (1+1/x+1/x^2)*q.
         * Again, (1+1/x+1/x^2) = EF in the field.
         */
        qef ^= q5b;

        /* 
         * Now that we have q5b = 5B * q and qef = EF * q 
         * we can fill two of the entries in the MDS matrix table. 
         * See the Twofish specifications for the order of the constants.
         */
        MDS_table[1][i] = q  <<24 | q5b<<16 | qef<<8 | qef;
        MDS_table[3][i] = q5b<<24 | qef<<16 | q  <<8 | q5b;

        /* Now we do it all again for the two columns that have a q1 box. */
        q = q_table[1][i];
        qef = (q >> 1) ^ mds_poly_divx_const[ q & 1 ];
        q5b = (qef >> 1) ^ mds_poly_divx_const[ qef & 1 ] ^ q;
        qef ^= q5b;

        /* The other two columns use the coefficient in a different order. */
        MDS_table[0][i] = qef<<24 | qef<<16 | q5b<<8 | q  ;
        MDS_table[2][i] = qef<<24 | q  <<16 | qef<<8 | q5b;
        }
    }



/* First a shorthand for the two q-tables */
#define q0  q_table[0]
#define q1  q_table[1]


#define H02( y, L )  MDS_table[0][q0[q0[y]^L[ 8]]^L[0]]
#define H12( y, L )  MDS_table[1][q0[q1[y]^L[ 9]]^L[1]]
#define H22( y, L )  MDS_table[2][q1[q0[y]^L[10]]^L[2]]
#define H32( y, L )  MDS_table[3][q1[q1[y]^L[11]]^L[3]]
#define H03( y, L )  H02( q1[y]^L[16], L )
#define H13( y, L )  H12( q1[y]^L[17], L )
#define H23( y, L )  H22( q0[y]^L[18], L )
#define H33( y, L )  H32( q0[y]^L[19], L )
#define H04( y, L )  H03( q1[y]^L[24], L )
#define H14( y, L )  H13( q0[y]^L[25], L )
#define H24( y, L )  H23( q0[y]^L[26], L )
#define H34( y, L )  H33( q1[y]^L[27], L )

/*
 * Now we can define the h() function given an array of key bytes. 
 * This function is only used in the key schedule, and not to pre-compute
 * the keyed S-boxes.
 *
 * In the key schedule, the input is always of the form k*(1+2^8+2^16+2^24)
 * so we only provide k as an argument.
 *
 * Arguments:
 * k        input to the h() function.
 * L        pointer to array of key bytes at 
 *          offsets 0,1,2,3, ... 8,9,10,11, [16,17,18,19, [24,25,26,27]]
 * kCycles  # key cycles, 2, 3, or 4.
 */
static UInt32 h( int k, Byte L[], int kCycles )
    {
    switch( kCycles ) {
        /* We code all 3 cases separately for speed reasons. */
    case 2:
        return H02(k,L) ^ H12(k,L) ^ H22(k,L) ^ H32(k,L);
    case 3:
        return H03(k,L) ^ H13(k,L) ^ H23(k,L) ^ H33(k,L);
    case 4:
        return H04(k,L) ^ H14(k,L) ^ H24(k,L) ^ H34(k,L);
    default: 
        /* This is always a coding error, which is fatal. */
        Twofish_fatal( "Twofish h(): Illegal argument" );
        }
    }


/*
 * Pre-compute the keyed S-boxes.
 * Fill the pre-computed S-box array in the expanded key structure.
 * Each pre-computed S-box maps 8 bits to 32 bits.
 *
 * The S argument contains half the number of bytes of the full key, but is
 * derived from the full key. 
 * S has the weird byte input order used by the Hxx macros.
 *
 * This function takes most of the time of a key expansion.
 *
 * Arguments:
 * S        pointer to array of 8*kCycles Bytes containing the S vector.
 * kCycles  number of key words, must be in the set {2,3,4}
 * xkey     pointer to Twofish_key structure that will contain the S-boxes.
 */
static void fill_keyed_sboxes( Byte S[], int kCycles, Twofish_key * xkey )
    {
    int i;
    switch( kCycles ) {
        /* We code all 3 cases separately for speed reasons. */
    case 2:
        for( i=0; i<256; i++ )
            {
            xkey->s[0][i]= H02( i, S );
            xkey->s[1][i]= H12( i, S );
            xkey->s[2][i]= H22( i, S );
            xkey->s[3][i]= H32( i, S );
            }
        break;
    case 3:
        for( i=0; i<256; i++ )
            {
            xkey->s[0][i]= H03( i, S );
            xkey->s[1][i]= H13( i, S );
            xkey->s[2][i]= H23( i, S );
            xkey->s[3][i]= H33( i, S );
            }
        break;
    case 4:
        for( i=0; i<256; i++ )
            {
            xkey->s[0][i]= H04( i, S );
            xkey->s[1][i]= H14( i, S );
            xkey->s[2][i]= H24( i, S );
            xkey->s[3][i]= H34( i, S );
            }
        break;
    default: 
        /* This is always a coding error, which is fatal. */
        Twofish_fatal( "Twofish fill_keyed_sboxes(): Illegal argument" );
        }
    }


/* A flag to keep track of whether we have been initialised or not. */
static int Twofish_initialised = 0;

void Twofish_initialise()
    {
    /* First test the various platform-specific definitions. */
    test_platform();

    /* We can now generate our tables, in the right order of course. */
    initialise_q_boxes();
    initialise_mds_tables();

    /* We're finished with the initialisation itself. */
    Twofish_initialised = 1;
    self_test();
    }

static unsigned int rs_poly_const[] = {0, 0x14d};
static unsigned int rs_poly_div_const[] = {0, 0xa6 };

void Twofish_prepare_key( Byte key[], int key_len, Twofish_key * xkey )
    {
    Byte K[32+32+4]; 

    int kCycles;        /* # key cycles, 2,3, or 4. */

    int i;
    UInt32 A, B;        /* Used to compute the round keys. */

    Byte * kptr;        /* Three pointers for the RS computation. */
    Byte * sptr;
    Byte * t;

    Byte b,bx,bxx;      /* Some more temporaries for the RS computation. */

    /* Check that the Twofish implementation was initialised. */
    if( Twofish_initialised == 0 )
        {
        Twofish_fatal( "Twofish implementation was not initialised." );
        for(;;);        /* Infinite loop, which beats being insecure. */
        }

    /* Check for valid key length. */
    if( key_len < 0 || key_len > 32 )
        {
        Twofish_fatal( "Twofish_prepare_key: illegal key length" );
        return;
        }

    /* Pad the key with zeroes to the next suitable key length. */
    memcpy( K, key, key_len );
    memset( K+key_len, 0, sizeof(K)-key_len );

    /* 
     * Compute kCycles: the number of key cycles used in the cipher. 
     * 2 for 128-bit keys, 3 for 192-bit keys, and 4 for 256-bit keys.
     */
    kCycles = (key_len + 7) >> 3;
    /* Handle the special case of very short keys: minimum 2 cycles. */
    if( kCycles < 2 )
        {
        kCycles = 2;
        }

    /* 
     * From now on we just pretend to have 8*kCycles bytes of 
     * key material in K. This handles all the key size cases. 
     */

    /* 
     * We first compute the 40 expanded key words, 
     * formulas straight from the Twofish specifications.
     */
    for( i=0; i<40; i+=2 )
        {
        /* 
         * Due to the byte spacing expected by the h() function 
         * we can pick the bytes directly from the key K.
         * As we use bytes, we never have the little/big endian
         * problem.
         *
         * Note that we apply the rotation function only to simple
         * variables, as the rotation macro might evaluate its argument
         * more than once.
         */
        A = h( i  , K  , kCycles );
        B = h( i+1, K+4, kCycles );
        B = ROL32( B, 8 );

        /* Compute and store the round keys. */
        A += B;
        B += A;
        xkey->K[i]   = A;
        xkey->K[i+1] = ROL32( B, 9 );
        }

    /* Wipe variables that contained key material. */
    A=B=0;
    kptr = K + 8*kCycles;           /* Start at end of key */
    sptr = K + 32;                  /* Start at start of S */

    /* Loop over all key material */
    while( kptr > K ) 
        {
        kptr -= 8;
        /* 
         * Initialise the polynimial in sptr[0..12]
         * The first four coefficients are 0 as we have to multiply by y^4.
         * The next 8 coefficients are from the key material.
         */
        memset( sptr, 0, 4 );
        memcpy( sptr+4, kptr, 8 );

        /* 
         * The 12 bytes starting at sptr are now the coefficients of
         * the polynomial we need to reduce.
         */

        /* Loop over the polynomial coefficients from high to low */
        t = sptr+11;
        /* Keep looping until polynomial is degree 3; */
        while( t > sptr+3 )
            {
            /* Pick up the highest coefficient of the poly. */
            b = *t;

            /* 
             * Compute x and (x+1/x) times this coefficient. 
             * See the MDS matrix implementation for a discussion of 
             * multiplication by x and 1/x. We just use different 
             * constants here as we are in a 
             * different finite field representation.
             *
             * These two statements set 
             * bx = (x) * b 
             * bxx= (x + 1/x) * b
             */
            bx = (Byte)((b<<1) ^ rs_poly_const[ b>>7 ]);
            bxx= (Byte)((b>>1) ^ rs_poly_div_const[ b&1 ] ^ bx);

            /*
             * Subtract suitable multiple of 
             * y^4 + (x + 1/x)y^3 + (x)y^2 + (x + 1/x)y + 1 
             * from the polynomial, except that we don't bother
             * updating t[0] as it will become zero anyway.
             */
            t[-1] ^= bxx;
            t[-2] ^= bx;
            t[-3] ^= bxx;
            t[-4] ^= b;
            
            /* Go to the next coefficient. */
            t--;
            }

        /* Go to next S-vector word, obeying the weird spacing rules. */
        sptr += 8;
        }

    /* Wipe variables that contained key material. */
    b = bx = bxx = 0;

    /* And finally, we can compute the key-dependent S-boxes. */
    fill_keyed_sboxes( &K[32], kCycles, xkey );

    /* Wipe array that contained key material. */
    memset( K, 0, sizeof( K ) );
    }


/*
 * We can now start on the actual encryption and decryption code.
 * As these are often speed-critical we will use a lot of macros.
 */

/*
 * The g() function is the heart of the round function.
 * We have two versions of the g() function, one without an input
 * rotation and one with.
 * The pre-computed S-boxes make this pretty simple.
 */
#define g0(X,xkey) \
 (xkey->s[0][b0(X)]^xkey->s[1][b1(X)]^xkey->s[2][b2(X)]^xkey->s[3][b3(X)])

#define g1(X,xkey) \
 (xkey->s[0][b3(X)]^xkey->s[1][b0(X)]^xkey->s[2][b1(X)]^xkey->s[3][b2(X)])

/*
 * A single round of Twofish. The A,B,C,D are the four state variables,
 * T0 and T1 are temporaries, xkey is the expanded key, and r the 
 * round number.
 *
 * Note that this macro does not implement the swap at the end of the round.
 */
#define ENCRYPT_RND( A,B,C,D, T0, T1, xkey, r ) \
    T0 = g0(A,xkey); T1 = g1(B,xkey);\
    C ^= T0+T1+xkey->K[8+2*(r)]; C = ROR32(C,1);\
    D = ROL32(D,1); D ^= T0+2*T1+xkey->K[8+2*(r)+1]

/*
 * Encrypt a single cycle, consisting of two rounds.
 * This avoids the swapping of the two halves. 
 * Parameter r is now the cycle number.
 */
#define ENCRYPT_CYCLE( A, B, C, D, T0, T1, xkey, r ) \
    ENCRYPT_RND( A,B,C,D,T0,T1,xkey,2*(r)   );\
    ENCRYPT_RND( C,D,A,B,T0,T1,xkey,2*(r)+1 )

/* Full 16-round encryption */
#define ENCRYPT( A,B,C,D,T0,T1,xkey ) \
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 0 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 1 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 2 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 3 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 4 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 5 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 6 );\
    ENCRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 7 )

/*
 * A single round of Twofish for decryption. It differs from
 * ENCRYTP_RND only because of the 1-bit rotations.
 */
#define DECRYPT_RND( A,B,C,D, T0, T1, xkey, r ) \
    T0 = g0(A,xkey); T1 = g1(B,xkey);\
    C = ROL32(C,1); C ^= T0+T1+xkey->K[8+2*(r)];\
    D ^= T0+2*T1+xkey->K[8+2*(r)+1]; D = ROR32(D,1)

/*
 * Decrypt a single cycle, consisting of two rounds. 
 * This avoids the swapping of the two halves. 
 * Parameter r is now the cycle number.
 */
#define DECRYPT_CYCLE( A, B, C, D, T0, T1, xkey, r ) \
    DECRYPT_RND( A,B,C,D,T0,T1,xkey,2*(r)+1 );\
    DECRYPT_RND( C,D,A,B,T0,T1,xkey,2*(r)   )

/* Full 16-round decryption. */
#define DECRYPT( A,B,C,D,T0,T1, xkey ) \
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 7 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 6 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 5 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 4 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 3 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 2 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 1 );\
    DECRYPT_CYCLE( A,B,C,D,T0,T1,xkey, 0 )

/*
 * A macro to read the state from the plaintext and do the initial key xors.
 * The koff argument allows us to use the same macro 
 * for the decryption which uses different key words at the start.
 */
#define GET_INPUT( src, A,B,C,D, xkey, koff ) \
    A = GET32(src   )^xkey->K[  koff]; B = GET32(src+ 4)^xkey->K[1+koff]; \
    C = GET32(src+ 8)^xkey->K[2+koff]; D = GET32(src+12)^xkey->K[3+koff]

/*
 * Similar macro to put the ciphertext in the output buffer.
 * We xor the keys into the state variables before we use the PUT32 
 * macro as the macro might use its argument multiple times.
 */
#define PUT_OUTPUT( A,B,C,D, dst, xkey, koff ) \
    A ^= xkey->K[  koff]; B ^= xkey->K[1+koff]; \
    C ^= xkey->K[2+koff]; D ^= xkey->K[3+koff]; \
    PUT32( A, dst   ); PUT32( B, dst+ 4 ); \
    PUT32( C, dst+8 ); PUT32( D, dst+12 )


/*
 * Twofish block encryption
 *
 * Arguments:
 * xkey         expanded key array
 * p            16 bytes of plaintext
 * c            16 bytes in which to store the ciphertext
 */
void Twofish_encrypt( Twofish_key * xkey, Byte p[16], Byte c[16])
    {
    UInt32 A,B,C,D,T0,T1;       /* Working variables */

    /* Get the four plaintext words xorred with the key */
    GET_INPUT( p, A,B,C,D, xkey, 0 );

    /* Do 8 cycles (= 16 rounds) */
    ENCRYPT( A,B,C,D,T0,T1,xkey );

    /* Store them with the final swap and the output whitening. */
    PUT_OUTPUT( C,D,A,B, c, xkey, 4 );
    }

/*
 * Twofish block decryption.
 *
 * Arguments:
 * xkey         expanded key array
 * p            16 bytes of plaintext
 * c            16 bytes in which to store the ciphertext
 */
void Twofish_decrypt( Twofish_key * xkey, Byte c[16], Byte p[16])
    {
    UInt32 A,B,C,D,T0,T1;       /* Working variables */

    /* Get the four plaintext words xorred with the key */
    GET_INPUT( c, A,B,C,D, xkey, 4 );

    /* Do 8 cycles (= 16 rounds) */
    DECRYPT( A,B,C,D,T0,T1,xkey );

    /* Store them with the final swap and the output whitening. */
    PUT_OUTPUT( C,D,A,B, p, xkey, 0 );
    }
