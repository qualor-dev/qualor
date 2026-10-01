<?php /** @var list<string> $names */ ?>
<ul>
<?php foreach ($names as $name): ?>
    <li><?= htmlspecialchars($name) ?></li>
<?php endforeach; ?>
</ul>
