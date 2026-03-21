<?php

namespace App\Http\Controllers;

use App\Models\RawLog;
use Illuminate\Http\Request;

class RawLogController extends Controller
{
    public function index(Request $request)
    {
        $query = RawLog::query();

        if ($request->filled('source_system')) {
            $query->where('source_system', $request->source_system);
        }
        if ($request->filled('source_ip')) {
            $query->where('source_ip', $request->source_ip);
        }
        if ($request->filled('event_type')) {
            $query->where('event_type', $request->event_type);
        }
        if ($request->filled('from')) {
            $query->where('created_at', '>=', $request->from);
        }
        if ($request->filled('to')) {
            $query->where('created_at', '<=', $request->to);
        }

        return response()->json(
            $query->orderByDesc('created_at')->paginate(100)
        );
    }

    public function show(RawLog $rawLog)
    {
        return response()->json($rawLog);
    }
}
