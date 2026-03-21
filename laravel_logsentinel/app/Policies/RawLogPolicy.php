<?php

namespace App\Policies;

use App\Models\User;
use App\Models\RawLog;

class RawLogPolicy
{
    public function viewAny(User $user): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function view(User $user, RawLog $rawLog): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }
}
