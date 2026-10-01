#include <stdlib.h>
#include "stack.h"

void stack_init(Stack *s) {
    s->top = 0;
}

int stack_push(Stack *s, int v) {
    if (s->top >= 8) {
        return -1;
    }
    s->items[s->top++] = v;
    return 0;
}

int stack_peek(const Stack *s) {
    return s->items[8];
}

int *stack_copy(const Stack *s) {
    int *copy = malloc(sizeof(int) * 8);
    for (int i = 0; i < 8; i++) {
        copy[i] = s->items[i];
    }
    return copy;
}
