import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/api_service.dart';

class RuleReviewScreen extends StatefulWidget {
  final int artifactId;
  final String filename;
  final Map<String, dynamic>? uploadResult;

  const RuleReviewScreen({
    super.key,
    required this.artifactId,
    required this.filename,
    this.uploadResult,
  });

  @override
  State<RuleReviewScreen> createState() => _RuleReviewScreenState();
}

class _RuleReviewScreenState extends State<RuleReviewScreen> {
  Map<String, dynamic>? _data;
  bool _loading = true;

  // Analyst checklist
  final Map<String, bool> _checklist = {
    'Rule name is descriptive':         false,
    'Strings section is relevant':      false,
    'Condition logic is correct':       false,
    'No false positive risk detected':  false,
    'Meta information is complete':     false,
    'Rule compiles without errors':     false,
  };

  @override
  void initState() {
    super.initState();
    if (widget.uploadResult != null) {
      // Use data from upload directly
      _data = widget.uploadResult;
      _loading = false;
      // Pre-check "compiles" if valid
      if (_data?['is_valid'] == true) {
        _checklist['Rule compiles without errors'] = true;
      }
    } else {
      _fetchRule();
    }
  }

  Future<void> _fetchRule() async {
    try {
      final d = await ApiService.getArtifactRule(widget.artifactId);
      setState(() {
        _data = {
          'yara_rule': d['rule']['rule_text'],
          'is_valid':  d['rule']['is_valid'] == 1,
          'indicators': d['indicators'],
        };
        if (_data?['is_valid'] == true) {
          _checklist['Rule compiles without errors'] = true;
        }
        _loading = false;
      });
    } catch (e) {
      setState(() => _loading = false);
    }
  }

  void _copyRule() {
    Clipboard.setData(ClipboardData(text: _data?['yara_rule'] ?? ''));
    ScaffoldMessenger.of(context).showSnackBar(
      const SnackBar(content: Text('YARA rule copied to clipboard')),
    );
  }

  int get _checklistScore =>
      _checklist.values.where((v) => v).length;

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF112240),
        title: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const Text('Rule Review', style: TextStyle(color: Colors.white)),
            Text(widget.filename,
                style: const TextStyle(color: Colors.white54, fontSize: 12)),
          ],
        ),
        iconTheme: const IconThemeData(color: Colors.white),
        actions: [
          if (_data != null)
            TextButton.icon(
              onPressed: _copyRule,
              icon: const Icon(Icons.copy, size: 16, color: Color(0xFF00D4FF)),
              label: const Text('Copy Rule',
                  style: TextStyle(color: Color(0xFF00D4FF))),
            ),
        ],
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(
              color: Color(0xFF00D4FF)))
          : _data == null
              ? const Center(
                  child: Text('No data', style: TextStyle(color: Colors.white54)))
              : _buildBody(),
    );
  }

  Widget _buildBody() {
    final indicators = List<Map<String, dynamic>>.from(
        _data?['indicators'] ?? []);
    final rule = _data?['yara_rule'] ?? '';
    final isValid = _data?['is_valid'] == true;

    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Left: YARA rule
          Expanded(
            flex: 3,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                // Status badge
                Row(children: [
                  Container(
                    padding: const EdgeInsets.symmetric(
                        horizontal: 12, vertical: 6),
                    decoration: BoxDecoration(
                      color: isValid
                          ? const Color(0xFF00FF88).withOpacity(0.1)
                          : Colors.red.withOpacity(0.1),
                      borderRadius: BorderRadius.circular(20),
                      border: Border.all(
                        color: isValid
                            ? const Color(0xFF00FF88)
                            : Colors.red,
                      ),
                    ),
                    child: Row(mainAxisSize: MainAxisSize.min, children: [
                      Icon(
                        isValid ? Icons.verified : Icons.error_outline,
                        color: isValid
                            ? const Color(0xFF00FF88)
                            : Colors.red,
                        size: 16,
                      ),
                      const SizedBox(width: 6),
                      Text(
                        isValid ? 'Rule Valid' : 'Validation Failed',
                        style: TextStyle(
                          color: isValid
                              ? const Color(0xFF00FF88)
                              : Colors.red,
                          fontWeight: FontWeight.bold,
                          fontSize: 13,
                        ),
                      ),
                    ]),
                  ),
                  const SizedBox(width: 12),
                  Text('${indicators.length} indicators extracted',
                      style: const TextStyle(
                          color: Colors.white54, fontSize: 13)),
                ]),
                const SizedBox(height: 16),

                // YARA rule box
                Container(
                  width: double.infinity,
                  decoration: BoxDecoration(
                    color: const Color(0xFF0A1628),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                        color: const Color(0xFF00D4FF).withOpacity(0.2)),
                  ),
                  child: Column(
                    crossAxisAlignment: CrossAxisAlignment.start,
                    children: [
                      Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 16, vertical: 10),
                        decoration: BoxDecoration(
                          border: Border(
                              bottom: BorderSide(
                                  color: const Color(0xFF00D4FF)
                                      .withOpacity(0.2))),
                        ),
                        child: Row(children: [
                          const Icon(Icons.code,
                              color: Color(0xFF00D4FF), size: 16),
                          const SizedBox(width: 8),
                          const Text('Generated YARA Rule',
                              style: TextStyle(
                                  color: Color(0xFF00D4FF),
                                  fontWeight: FontWeight.bold,
                                  fontSize: 13)),
                          const Spacer(),
                          Text('yara-python validated',
                              style: TextStyle(
                                  color: Colors.white38, fontSize: 11)),
                        ]),
                      ),
                      Padding(
                        padding: const EdgeInsets.all(16),
                        child: SelectableText(
                          rule,
                          style: const TextStyle(
                            fontFamily: 'monospace',
                            fontSize: 13,
                            color: Color(0xFFE2E8F0),
                            height: 1.6,
                          ),
                        ),
                      ),
                    ],
                  ),
                ),

                const SizedBox(height: 20),

                // Indicators
                if (indicators.isNotEmpty) ...[
                  const Text('Extracted Indicators',
                      style: TextStyle(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 16)),
                  const SizedBox(height: 10),
                  Wrap(
                    spacing: 8,
                    runSpacing: 8,
                    children: indicators.map((ind) {
                      final color = _indicatorColor(ind['type'] ?? '');
                      return Container(
                        padding: const EdgeInsets.symmetric(
                            horizontal: 10, vertical: 6),
                        decoration: BoxDecoration(
                          color: color.withOpacity(0.08),
                          borderRadius: BorderRadius.circular(6),
                          border:
                              Border.all(color: color.withOpacity(0.3)),
                        ),
                        child: Row(mainAxisSize: MainAxisSize.min, children: [
                          Container(
                            width: 6, height: 6,
                            decoration: BoxDecoration(
                                color: color, shape: BoxShape.circle),
                          ),
                          const SizedBox(width: 6),
                          Text(
                            '${ind['type']}: ',
                            style: TextStyle(
                                color: color,
                                fontSize: 11,
                                fontWeight: FontWeight.bold),
                          ),
                          Text(
                            (ind['value'] as String).length > 30
                                ? '${(ind['value'] as String).substring(0, 30)}…'
                                : ind['value'],
                            style: const TextStyle(
                                color: Colors.white70,
                                fontSize: 11,
                                fontFamily: 'monospace'),
                          ),
                        ]),
                      );
                    }).toList(),
                  ),
                ],
              ],
            ),
          ),

          const SizedBox(width: 24),

          // Right: Analyst checklist
          SizedBox(
            width: 280,
            child: Container(
              padding: const EdgeInsets.all(20),
              decoration: BoxDecoration(
                color: const Color(0xFF112240),
                borderRadius: BorderRadius.circular(12),
                border: Border.all(color: Colors.white12),
              ),
              child: Column(
                crossAxisAlignment: CrossAxisAlignment.start,
                children: [
                  const Text('Analyst Review Checklist',
                      style: TextStyle(
                          color: Colors.white,
                          fontWeight: FontWeight.bold,
                          fontSize: 15)),
                  const SizedBox(height: 4),
                  const Text(
                      'Review the rule before approving for deployment.',
                      style: TextStyle(
                          color: Colors.white38, fontSize: 11)),
                  const SizedBox(height: 16),

                  // Score bar
                  Row(children: [
                    Text('$_checklistScore/${_checklist.length}',
                        style: const TextStyle(
                            color: Color(0xFF00D4FF),
                            fontWeight: FontWeight.bold)),
                    const SizedBox(width: 8),
                    Expanded(
                      child: ClipRRect(
                        borderRadius: BorderRadius.circular(4),
                        child: LinearProgressIndicator(
                          value: _checklistScore / _checklist.length,
                          backgroundColor: Colors.white12,
                          valueColor: AlwaysStoppedAnimation(
                            _checklistScore == _checklist.length
                                ? const Color(0xFF00FF88)
                                : const Color(0xFF00D4FF),
                          ),
                          minHeight: 6,
                        ),
                      ),
                    ),
                  ]),
                  const SizedBox(height: 16),

                  ..._checklist.keys.map((k) => CheckboxListTile(
                        dense: true,
                        contentPadding: EdgeInsets.zero,
                        title: Text(k,
                            style: const TextStyle(
                                color: Colors.white70, fontSize: 13)),
                        value: _checklist[k],
                        activeColor: const Color(0xFF00D4FF),
                        checkColor: const Color(0xFF0D1B2A),
                        onChanged: (v) =>
                            setState(() => _checklist[k] = v ?? false),
                      )),

                  const SizedBox(height: 16),
                  const Divider(color: Colors.white12),
                  const SizedBox(height: 12),

                  SizedBox(
                    width: double.infinity,
                    child: ElevatedButton.icon(
                      onPressed: _checklistScore == _checklist.length
                          ? _copyRule
                          : null,
                      icon: const Icon(Icons.download, size: 16),
                      label: const Text('Export Rule'),
                      style: ElevatedButton.styleFrom(
                        backgroundColor: const Color(0xFF00FF88),
                        foregroundColor: const Color(0xFF0D1B2A),
                        disabledBackgroundColor: Colors.white12,
                        disabledForegroundColor: Colors.white38,
                        shape: RoundedRectangleBorder(
                            borderRadius: BorderRadius.circular(8)),
                      ),
                    ),
                  ),
                  if (_checklistScore < _checklist.length)
                    const Padding(
                      padding: EdgeInsets.only(top: 8),
                      child: Text(
                          'Complete all checklist items to export.',
                          style: TextStyle(
                              color: Colors.white38, fontSize: 11),
                          textAlign: TextAlign.center),
                    ),
                ],
              ),
            ),
          ),
        ],
      ),
    );
  }

  Color _indicatorColor(String type) {
    switch (type) {
      case 'ip_address':   return Colors.redAccent;
      case 'domain':       return Colors.orangeAccent;
      case 'url':          return Colors.purpleAccent;
      case 'registry_key': return Colors.yellowAccent;
      case 'file_path':    return Colors.blueAccent;
      case 'api_import':   return const Color(0xFF00FF88);
      case 'file':         return Colors.tealAccent;
      default:             return const Color(0xFF00D4FF);
    }
  }
}
