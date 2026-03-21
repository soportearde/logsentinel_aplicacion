<?php

namespace App\Http\Controllers;

use App\Models\CorrelationRule;
use Illuminate\Http\Request;

class CorrelationRuleController extends Controller
{
    public function index()
    {
        return response()->json(
            CorrelationRule::with('severity')->orderBy('rule_name')->get()
        );
    }

    public function store(Request $request)
    {
        $data = $request->validate([
            'rule_name'   => 'required|string|unique:alerts_db.correlation_rules,rule_name',
            'description' => 'nullable|string',
            'severity_id' => 'required|integer',
            'enabled'     => 'boolean',
            'conditions'  => 'nullable|array',
        ]);

        $rule = CorrelationRule::create($data);

        return response()->json($rule, 201);
    }

    public function show(CorrelationRule $correlationRule)
    {
        return response()->json($correlationRule->load('severity'));
    }

    public function update(Request $request, CorrelationRule $correlationRule)
    {
        $data = $request->validate([
            'rule_name'   => 'sometimes|string|unique:alerts_db.correlation_rules,rule_name,' . $correlationRule->id,
            'description' => 'nullable|string',
            'severity_id' => 'sometimes|integer',
            'enabled'     => 'boolean',
            'conditions'  => 'nullable|array',
        ]);

        $correlationRule->update($data);

        return response()->json($correlationRule);
    }

    public function destroy(CorrelationRule $correlationRule)
    {
        $correlationRule->delete();

        return response()->json(['message' => 'Regla eliminada.']);
    }
}
