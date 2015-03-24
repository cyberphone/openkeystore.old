#define DATA_ORDER_IS_BIG_ENDIAN

/*
 * Engage compiler specific rotate intrinsic function if available.
 */
#undef ROTATE
#ifndef PEDANTIC
# if defined(_MSC_VER) || defined(__ICC)
#  define ROTATE(a,n)   _lrotl(a,n)
# elif defined(__MWERKS__)
#  if defined(__POWERPC__)
#   define ROTATE(a,n)  __rlwinm(a,n,0,31)
#  elif defined(__MC68K__)
    /* Motorola specific tweak. <appro@fy.chalmers.se> */
#   define ROTATE(a,n)  ( n<24 ? __rol(a,n) : __ror(a,32-n) )
#  else
#   define ROTATE(a,n)  __rol(a,n)
#  endif
# elif defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
  /*
   * Some GNU C inline assembler templates. Note that these are
   * rotates by *constant* number of bits! But that's exactly
   * what we need here...
   *                    <appro@fy.chalmers.se>
   */
#  if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
#   define ROTATE(a,n)  ({ register unsigned int ret;   \
                asm (           \
                "roll %1,%0"        \
                : "=r"(ret)     \
                : "I"(n), "0"(a)    \
                : "cc");        \
               ret;             \
            })
#  elif defined(_ARCH_PPC) || defined(_ARCH_PPC64) || \
    defined(__powerpc) || defined(__ppc__) || defined(__powerpc64__)
#   define ROTATE(a,n)  ({ register unsigned int ret;   \
                asm (           \
                "rlwinm %0,%1,%2,0,31"  \
                : "=r"(ret)     \
                : "r"(a), "I"(n));  \
               ret;             \
            })
#  elif defined(__s390x__)
#   define ROTATE(a,n) ({ register unsigned int ret;    \
                asm ("rll %0,%1,%2" \
                : "=r"(ret)     \
                : "r"(a), "I"(n));  \
              ret;              \
            })
#  endif
# endif
#endif /* PEDANTIC */

#ifndef ROTATE
#define ROTATE(a,n)     (((a)<<(n))|(((a)&0xffffffff)>>(32-(n))))
#endif

#if defined(DATA_ORDER_IS_BIG_ENDIAN)

#ifndef PEDANTIC
# if defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#  if ((defined(__i386) || defined(__i386__)) && !defined(I386_ONLY)) || \
      (defined(__x86_64) || defined(__x86_64__))
#   if !defined(B_ENDIAN)
    /*
     * This gives ~30-40% performance improvement in SHA-256 compiled
     * with gcc [on P4]. Well, first macro to be frank. We can pull
     * this trick on x86* platforms only, because these CPUs can fetch
     * unaligned data without raising an exception.
     */
#   define HOST_c2l(c,l)    ({ unsigned int r=*((const unsigned int *)(c)); \
                   asm ("bswapl %0":"=r"(r):"0"(r));    \
                   (c)+=4; (l)=r;           })
#   define HOST_l2c(l,c)    ({ unsigned int r=(l);          \
                   asm ("bswapl %0":"=r"(r):"0"(r));    \
                   *((unsigned int *)(c))=r; (c)+=4; r; })
#   endif
#  endif
# endif
#endif
#if defined(__s390__) || defined(__s390x__)
# define HOST_c2l(c,l) ((l)=*((const unsigned int *)(c)), (c)+=4, (l))
# define HOST_l2c(l,c) (*((unsigned int *)(c))=(l), (c)+=4, (l))
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)   (l =(((unsigned long)(*((c)++)))<<24),      \
             l|=(((unsigned long)(*((c)++)))<<16),      \
             l|=(((unsigned long)(*((c)++)))<< 8),      \
             l|=(((unsigned long)(*((c)++)))    ),      \
             l)
#endif
#ifndef HOST_l2c
#define HOST_l2c(l,c)   (*((c)++)=(unsigned char)(((l)>>24)&0xff),  \
             *((c)++)=(unsigned char)(((l)>>16)&0xff),  \
             *((c)++)=(unsigned char)(((l)>> 8)&0xff),  \
             *((c)++)=(unsigned char)(((l)    )&0xff),  \
             l)
#endif

#elif defined(DATA_ORDER_IS_LITTLE_ENDIAN)

#ifndef PEDANTIC
# if defined(__GNUC__) && __GNUC__>=2 && !defined(OPENSSL_NO_ASM) && !defined(OPENSSL_NO_INLINE_ASM)
#  if defined(__s390x__)
#   define HOST_c2l(c,l)    ({ asm ("lrv    %0,0(%1)"       \
                    :"=r"(l) : "r"(c));     \
                   (c)+=4; (l);             })
#   define HOST_l2c(l,c)    ({ asm ("strv   %0,0(%1)"       \
                    : : "r"(l),"r"(c) : "memory");  \
                   (c)+=4; (l);             })
#  endif
# endif
#endif
#if defined(__i386) || defined(__i386__) || defined(__x86_64) || defined(__x86_64__)
# ifndef B_ENDIAN
   /* See comment in DATA_ORDER_IS_BIG_ENDIAN section. */
#  define HOST_c2l(c,l) ((l)=*((const unsigned int *)(c)), (c)+=4, l)
#  define HOST_l2c(l,c) (*((unsigned int *)(c))=(l), (c)+=4, l)
# endif
#endif

#ifndef HOST_c2l
#define HOST_c2l(c,l)   (l =(((unsigned long)(*((c)++)))    ),      \
             l|=(((unsigned long)(*((c)++)))<< 8),      \
             l|=(((unsigned long)(*((c)++)))<<16),      \
             l|=(((unsigned long)(*((c)++)))<<24),      \
             l)
#endif
#ifndef HOST_l2c
#define HOST_l2c(l,c)   (*((c)++)=(unsigned char)(((l)    )&0xff),  \
             *((c)++)=(unsigned char)(((l)>> 8)&0xff),  \
             *((c)++)=(unsigned char)(((l)>>16)&0xff),  \
             *((c)++)=(unsigned char)(((l)>>24)&0xff),  \
             l)
#endif

#endif
