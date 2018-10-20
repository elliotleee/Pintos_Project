#ifndef _FLOAT_NUM_H
#define _FLOAT_NUM_H

typedef long long fp_t;

#define FD_SHIFT_AMOUNT 16

// X is a fp_t variable N is a int variable
 
#define INT_TO_FD(N) ((fp_t)(N << FD_SHIFT_AMOUNT))
// convet int into float
#define FD_TO_INT_PART(X) ( X >> FD_SHIFT_AMOUNT )
// get the int part of a float
#define FD_TO_INT_NEAR(X) ( X >=0 ? (( X +(1<<(FD_SHIFT_AMOUNT-1)))>>FD_SHIFT_AMOUNT): ((X - (1<<(FD_SHIFT_AMOUNT-1)))>>FD_SHIFT_AMOUNT) )
// 
#define FD_ADD(X, Y)   ( X + Y )
#define FD_SUB(X, Y)   ( X - Y )
#define FD_ADD_N(X, N) ( X  + (N<<FD_SHIFT_AMOUNT))
#define FD_SUB_N(X, N) ( X  - (N<<FD_SHIFT_AMOUNT))
#define FD_MUL(X, Y)   (((fp_t)X)* Y >>FD_SHIFT_AMOUNT)
#define FD_MUL_N(X, N) (X*N)
#define FD_DIV(X, Y) ((((fp_t)X)<<FD_SHIFT_AMOUNT)/(Y))
#define FD_DIV_N(X, N) ((X)/N)


#endif

