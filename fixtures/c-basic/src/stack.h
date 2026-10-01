#ifndef STACK_H
#define STACK_H

/* A fixed-size integer stack. */
typedef struct {
    int items[8];
    int top;
} Stack;

void stack_init(Stack *s);
int stack_push(Stack *s, int v);
int stack_peek(const Stack *s);

#endif
