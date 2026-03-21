<?php

use Illuminate\Support\Facades\Route;
use App\Http\Controllers\AuthController;
use App\Http\Controllers\DashboardController;
use App\Http\Controllers\AlertController;
use App\Http\Controllers\RawLogController;
use App\Http\Controllers\CorrelationRuleController;
use App\Http\Controllers\UserController;
use App\Http\Controllers\ReportController;

// ── Auth (público) ─────────────────────────────────────────────────────────
Route::post('/login', [AuthController::class, 'login']);

// ── Rutas protegidas ───────────────────────────────────────────────────────
Route::middleware('auth:sanctum')->group(function () {

    // Auth
    Route::post('/logout', [AuthController::class, 'logout']);
Route::get('/me',      [AuthController::class, 'me']);
    // Dashboard (todos los roles autenticados)
    Route::get('/dashboard', [DashboardController::class, 'index']);

    // Alertas (analyst + admin)
    Route::middleware('can:viewAny,App\Models\Alert')->group(function () {
        Route::get('/alerts',              [AlertController::class, 'index']);
        Route::get('/alerts/{alert}',      [AlertController::class, 'show']);
        Route::patch('/alerts/{alert}/status', [AlertController::class, 'updateStatus']);
    });

    // Logs en bruto (analyst + admin)
    Route::middleware('can:viewAny,App\Models\RawLog')->group(function () {
        Route::get('/raw-logs',           [RawLogController::class, 'index']);
        Route::get('/raw-logs/{rawLog}',  [RawLogController::class, 'show']);
    });

    // Informes (analyst + admin)
    Route::middleware('can:viewAny,App\Models\Report')->group(function () {
        Route::get('/reports',                    [ReportController::class, 'index']);
        Route::post('/reports',                   [ReportController::class, 'store']);
        Route::get('/reports/{report}',           [ReportController::class, 'show']);
        Route::get('/reports/{report}/download',  [ReportController::class, 'download']);
        Route::delete('/reports/{report}',        [ReportController::class, 'destroy']);
    });

    // Reglas de correlación (solo admin)
    Route::middleware('can:viewAny,App\Models\CorrelationRule')->group(function () {
        Route::apiResource('correlation-rules', CorrelationRuleController::class);
    });

    // Usuarios (solo admin)
    Route::middleware('can:viewAny,App\Models\User')->group(function () {
        Route::get('/roles', [UserController::class, 'roles']);
        Route::apiResource('users', UserController::class);
    });
});
