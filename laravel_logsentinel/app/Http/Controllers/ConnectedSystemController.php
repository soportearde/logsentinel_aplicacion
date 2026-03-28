<?php

namespace App\Http\Controllers;

use App\Models\ConnectedSystem;
use Illuminate\Http\Request;

class ConnectedSystemController extends Controller
{
    /**
     * Lista todos los sistemas conectados.
     */
    public function index()
    {
        $systems = ConnectedSystem::orderByDesc('created_at')->get();

        return response()->json($systems);
    }

    /**
     * Muestra un sistema concreto.
     */
    public function show(ConnectedSystem $connectedSystem)
    {
        return response()->json($connectedSystem);
    }

    /**
     * Registra un nuevo sistema y genera su API key.
     */
    public function store(Request $request)
    {
        $request->validate([
            'system_name' => 'required|string|max:100',
            'system_type' => 'nullable|string|max:50',
            'description' => 'nullable|string',
        ]);

        $system = ConnectedSystem::create([
            'system_name' => $request->system_name,
            'system_type' => $request->system_type ?? 'ubuntu',
            'description' => $request->description,
            'api_key'     => ConnectedSystem::generateApiKey(),
            'status'      => 'pending',
        ]);

        return response()->json($system, 201);
    }

    /**
     * Actualiza un sistema existente.
     */
    public function update(Request $request, ConnectedSystem $connectedSystem)
    {
        $request->validate([
            'system_name' => 'sometimes|string|max:100',
            'system_type' => 'sometimes|string|max:50',
            'description' => 'nullable|string',
        ]);

        $connectedSystem->update($request->only([
            'system_name', 'system_type', 'description',
        ]));

        return response()->json($connectedSystem);
    }

    /**
     * Elimina un sistema.
     */
    public function destroy(ConnectedSystem $connectedSystem)
    {
        $connectedSystem->delete();

        return response()->json(['message' => 'Sistema eliminado']);
    }

    /**
     * Devuelve el comando de instalación para un sistema.
     * El admin lo copia y lo pega en el servidor Ubuntu.
     */
    public function installCommand(ConnectedSystem $connectedSystem, Request $request)
    {
        // URL base del LogCollector (ajustar a tu IP/dominio)
        $baseUrl = $request->query('base_url', 'http://20.238.17.71');

        return response()->json([
            'system_name'     => $connectedSystem->system_name,
            'api_key'         => $connectedSystem->api_key,
            'install_command' => $connectedSystem->getInstallCommand($baseUrl),
        ]);
    }

    /**
     * Descarga el plugin de WordPress con la API key y el endpoint ya inyectados.
     */
    public function downloadPlugin(ConnectedSystem $connectedSystem, Request $request)
    {
        $pluginPath = base_path('../agent/plugin-wordpress.php');

        if (!file_exists($pluginPath)) {
            return response()->json(['error' => 'Plugin no encontrado en el servidor'], 404);
        }

        $content = file_get_contents($pluginPath);

        // Sustituimos el endpoint por la URL real del servidor
        $baseUrl = $request->query('base_url', 'http://20.238.17.71');
        $endpoint = rtrim($baseUrl, '/') . '/api/log';
        $content = preg_replace(
            "/define\s*\(\s*'LOGSENTINEL_ENDPOINT'\s*,\s*'[^']*'\s*\)/",
            "define( 'LOGSENTINEL_ENDPOINT', '{$endpoint}' )",
            $content
        );

        // Inyectamos la API key como constante
        $content = str_replace(
            "define( 'LOGSENTINEL_ENDPOINT'",
            "define( 'LOGSENTINEL_API_KEY', '" . addslashes($connectedSystem->api_key) . "' );\ndefine( 'LOGSENTINEL_ENDPOINT'",
            $content
        );

        // Añadimos la X-API-Key a la cabecera del wp_remote_post
        $content = str_replace(
            "'headers'   => [ 'Content-Type' => 'application/json' ]",
            "'headers'   => [ 'Content-Type' => 'application/json', 'X-API-Key' => LOGSENTINEL_API_KEY ]",
            $content
        );

        $safeName = preg_replace('/[^a-zA-Z0-9_-]/', '_', $connectedSystem->system_name);
        $filename = "logsentinel-wp-{$safeName}.php";

        return response($content, 200, [
            'Content-Type'        => 'application/octet-stream',
            'Content-Disposition' => "attachment; filename=\"{$filename}\"",
        ]);
    }

    /**
     * Regenera la API key de un sistema (por si se compromete).
     */
    public function regenerateKey(ConnectedSystem $connectedSystem)
    {
        $connectedSystem->update([
            'api_key' => ConnectedSystem::generateApiKey(),
            'status'  => 'pending', // vuelve a pendiente porque la key cambió
        ]);

        return response()->json($connectedSystem);
    }

    /**
     * Heartbeat — el agente llama aquí para decir "estoy vivo".
     * Este endpoint NO necesita auth de Sanctum, se autentica por API key.
     */
    public function heartbeat(Request $request)
    {
        $apiKey = $request->header('X-API-Key');

        if (!$apiKey) {
            return response()->json(['error' => 'Falta X-API-Key'], 401);
        }

        $system = ConnectedSystem::where('api_key', $apiKey)->first();

        if (!$system) {
            return response()->json(['error' => 'API key no reconocida'], 401);
        }

        $system->update([
            'status'     => 'active',
            'last_seen'  => now(),
            'ip_address' => $request->ip(),
        ]);

        return response()->json([
            'status'      => 'ok',
            'system_name' => $system->system_name,
        ]);
    }
}
