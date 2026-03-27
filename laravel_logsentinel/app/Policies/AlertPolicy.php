<?php

namespace App\Policies;

use App\Models\User;
use App\Models\Alert;

class AlertPolicy
{
    public function viewAny(User $user): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function view(User $user, Alert $alert): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function update(User $user, Alert $alert): bool
    {
        return in_array($user->role?->name, ['analyst', 'admin']);
    }

    public function delete(User $user, Alert $alert): bool
    {
        return $user->role?->name === 'admin';
    }
}
