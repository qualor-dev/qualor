<?php

declare(strict_types=1);

namespace Shop\Tests;

use PHPUnit\Framework\TestCase;
use Shop\Cart;

final class CartTest extends TestCase
{
    public function testAdd(): void
    {
        $cart = new Cart();
        $cart->add('apple', 2);
        self::assertSame('bronze', $cart->tier(5));
    }
}
