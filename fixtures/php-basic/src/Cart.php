<?php

declare(strict_types=1);

namespace Shop;

/**
 * A shopping cart (the fixture's PHPStan findings are deliberate).
 */
final class Cart
{
    /** @var array<string, int> */
    private array $items = [];

    private int $discount = 0;

    public function add(string $sku, int $quantity = 1): void
    {
        if ($quantity <= 0 || $sku === '') {
            return;
        }
        $this->items[$sku] = ($this->items[$sku] ?? 0) + $quantity;
    }

    public function count(): int
    {
        $total = 0;
        foreach ($this->items as $quantity) {
            $total += $quantity;
        }
        return $totl;
    }

    public function label(string $sku): string
    {
        $length = strlen($sku, 10);
        return $length > 3 ? substr($sku, 0, 3) : $sku;
    }

    public function clear(): void
    {
        $this->items = [];
    }

    public function reset(): int
    {
        return $this->clear();
    }

    /**
     * @param string $total the order total
     */
    public function tier(int $total): string
    {
        switch (true) {
            case $total > 1000:
                return 'gold';
            case $total > 100:
                return 'silver';
            default:
                return 'bronze';
        }
    }

    public function describe(int $code): string
    {
        return match ($code) {
            1, 2 => 'few',
            3 => 'some',
            default => 'many',
        };
    }
}
