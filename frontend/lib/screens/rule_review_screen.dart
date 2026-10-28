import 'package:flutter/material.dart';
import 'package:flutter/services.dart';
import '../services/api_service.dart';
import '../services/file_download.dart';

const _bg = Color(0xFF0D1B2A);
const _panel = Color(0xFF112240);
const _cyan = Color(0xFF00D4FF);
const _green = Color(0xFF00FF88);

// Used until the server sends its list (it checks the same items on approve)
const _defaultChecklist = [
  'Rule name is descriptive',
  'Strings section is relevant',
  'Condition logic is correct',
  'No false positive risk detected',
  'Meta information is complete',
  'Rule compiles without errors',
];
const _compilesItem = 'Rule compiles without errors';

class RuleReviewScreen extends StatefulWidget {
  final int artifactId;
  final String filename;
  // Kept for callers; the screen always loads the saved rule from the server
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
  Map<String, dynamic>? _rule;
  List<Map<String, dynamic>> _indicators = [];
  List<String> _checklistItems = _defaultChecklist;
  Map<String, bool> _checklist = {};
  bool _loading = true;
  String? _loadError;

  final _editor = TextEditingController();
  final _note = TextEditingController();
  String _savedText = '';
  String? _compileError;   // YARA error from the last failed save
  bool _saving = false;
  bool _approving = false;
  bool _exporting = false;

  bool get _dirty => _editor.text != _savedText;
  bool get _isValid => _rule?['is_valid'] == 1 || _rule?['is_valid'] == true;
  bool get _approved => _rule?['status'] == 'approved';
  int get _ruleId => _rule!['id'] as int;
  int get _checklistScore => _checklist.values.where((v) => v).length;
  bool get _checklistComplete =>
      _checklistItems.every((item) => _checklist[item] == true);

  @override
  void initState() {
    super.initState();
    _editor.addListener(() => setState(() {}));
    _fetchRule();
  }

  @override
  void dispose() {
    _editor.dispose();
    _note.dispose();
    super.dispose();
  }

  Future<void> _fetchRule() async {
    try {
      final d = await ApiService.getArtifactRule(widget.artifactId);
      if (!mounted) return;
      setState(() {
        _indicators = List<Map<String, dynamic>>.from(d['indicators'] ?? []);
        _checklistItems = List<String>.from(
            d['checklist_items'] ?? _defaultChecklist);
        _applyRule(Map<String, dynamic>.from(d['rule']));
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _loadError = e.toString();
        _loading = false;
      });
    }
  }

  // Shows a rule from the server and resets the checklist: an approved rule
  // keeps its ticks, any new version must be reviewed again.
  void _applyRule(Map<String, dynamic> rule) {
    _rule = rule;
    _savedText = rule['rule_text'] ?? '';
    _editor.text = _savedText;
    _compileError = null;
    _checklist = {
      for (final item in _checklistItems)
        item: _approved || (item == _compilesItem && _isValid),
    };
  }

  void _snack(String message, {bool error = false}) {
    ScaffoldMessenger.of(context).showSnackBar(SnackBar(
      content: Text(message),
      backgroundColor: error ? Colors.red.shade700 : null,
    ));
  }

  void _copyRule() {
    Clipboard.setData(ClipboardData(text: _editor.text));
    _snack('YARA rule copied to clipboard');
  }

  Future<void> _save() async {
    if (!_dirty || _saving) return;
    setState(() {
      _saving = true;
      _compileError = null;
    });
    try {
      final r = await ApiService.editRule(_ruleId, _editor.text, _note.text);
      if (!mounted) return;
      setState(() {
        _applyRule(Map<String, dynamic>.from(r['rule']));
        _note.clear();
      });
      _snack(r['message'] ?? 'Saved');
    } on ApiException catch (e) {
      if (!mounted) return;
      if (e.statusCode == 422) {
        setState(() => _compileError = e.message);
      } else {
        _snack(e.message, error: true);
      }
    } catch (e) {
      if (mounted) _snack('$e', error: true);
    } finally {
      if (mounted) setState(() => _saving = false);
    }
  }

  Future<void> _approve() async {
    setState(() => _approving = true);
    try {
      final r = await ApiService.approveRule(_ruleId, _checklist);
      if (!mounted) return;
      setState(() => _applyRule(Map<String, dynamic>.from(r['rule'])));
      _snack('Rule approved');
    } catch (e) {
      if (mounted) _snack('$e', error: true);
    } finally {
      if (mounted) setState(() => _approving = false);
    }
  }

  Future<void> _export() async {
    setState(() => _exporting = true);
    try {
      final file = await ApiService.exportRule(_ruleId);
      await saveFile(file.filename, file.bytes);
      if (mounted) _snack('Downloaded ${file.filename}');
    } catch (e) {
      if (mounted) _snack('$e', error: true);
    } finally {
      if (mounted) setState(() => _exporting = false);
    }
  }

  Future<void> _showHistory() async {
    final restored = await showDialog<String>(
      context: context,
      builder: (_) => _VersionHistoryDialog(
        ruleId: _ruleId,
        currentVersion: _rule?['current_version'] ?? 1,
        hasUnsavedChanges: _dirty,
      ),
    );
    if (restored != null && mounted) {
      _snack(restored);
      _fetchRule();
    }
  }

  Future<bool> _confirmDiscard() async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _panel,
        title: const Text('Discard unsaved changes?'),
        content: const Text('Your edits to this rule have not been saved.'),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Keep editing')),
          TextButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Discard',
                  style: TextStyle(color: Colors.redAccent))),
        ],
      ),
    );
    return ok ?? false;
  }

  @override
  Widget build(BuildContext context) {
    return PopScope(
      canPop: !_dirty,
      onPopInvokedWithResult: (didPop, _) async {
        if (didPop) return;
        // Navigator.pop doesn't go through PopScope, so this closes the screen
        if (await _confirmDiscard() && mounted) Navigator.pop(context);
      },
      child: Scaffold(
        backgroundColor: _bg,
        appBar: AppBar(
          backgroundColor: _panel,
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
            if (_rule != null) ...[
              TextButton.icon(
                onPressed: _showHistory,
                icon: const Icon(Icons.history, size: 16, color: _cyan),
                label: const Text('History', style: TextStyle(color: _cyan)),
              ),
              TextButton.icon(
                onPressed: _copyRule,
                icon: const Icon(Icons.copy, size: 16, color: _cyan),
                label: const Text('Copy Rule', style: TextStyle(color: _cyan)),
              ),
            ],
          ],
        ),
        body: _loading
            ? const Center(child: CircularProgressIndicator(color: _cyan))
            : _rule == null
                ? Center(
                    child: Text(_loadError ?? 'No data',
                        style: const TextStyle(color: Colors.white54)))
                : _buildBody(),
      ),
    );
  }

  Widget _buildBody() {
    return SingleChildScrollView(
      padding: const EdgeInsets.all(24),
      child: Row(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          // Left: rule editor
          Expanded(
            flex: 3,
            child: Column(
              crossAxisAlignment: CrossAxisAlignment.start,
              children: [
                _buildStatusRow(),
                const SizedBox(height: 16),
                _buildEditor(),
                if (_compileError != null) ...[
                  const SizedBox(height: 12),
                  _buildCompileError(),
                ],
                const SizedBox(height: 12),
                _buildSaveRow(),
                const SizedBox(height: 20),
                if (_indicators.isNotEmpty) _buildIndicators(),
              ],
            ),
          ),
          const SizedBox(width: 24),
          // Right: review, approve, export
          SizedBox(width: 300, child: _buildReviewPanel()),
        ],
      ),
    );
  }

  Widget _buildStatusRow() {
    return Wrap(
      spacing: 10,
      runSpacing: 8,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        _approved
            ? _pill('Approved', _green, Icons.verified_user)
            : _pill('Draft', Colors.amberAccent, Icons.edit_note),
        _pill('Version ${_rule?['current_version'] ?? 1}', _cyan, Icons.layers),
        _isValid
            ? _pill('Rule Valid', _green, Icons.verified)
            : _pill('Validation Failed', Colors.red, Icons.error_outline),
        Text('${_indicators.length} indicators extracted',
            style: const TextStyle(color: Colors.white54, fontSize: 13)),
      ],
    );
  }

  Widget _pill(String label, Color color, IconData icon) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12, vertical: 6),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(20),
        border: Border.all(color: color),
      ),
      child: Row(mainAxisSize: MainAxisSize.min, children: [
        Icon(icon, color: color, size: 16),
        const SizedBox(width: 6),
        Text(label,
            style: TextStyle(
                color: color, fontWeight: FontWeight.bold, fontSize: 13)),
      ]),
    );
  }

  Widget _buildEditor() {
    return Container(
      width: double.infinity,
      decoration: BoxDecoration(
        color: const Color(0xFF0A1628),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(
            color: _dirty
                ? Colors.orangeAccent.withValues(alpha: 0.6)
                : _cyan.withValues(alpha: 0.2)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        children: [
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 16, vertical: 10),
            decoration: BoxDecoration(
              border: Border(
                  bottom: BorderSide(color: _cyan.withValues(alpha: 0.2))),
            ),
            child: Row(children: [
              const Icon(Icons.code, color: _cyan, size: 16),
              const SizedBox(width: 8),
              const Text('Generated YARA Rule',
                  style: TextStyle(
                      color: _cyan, fontWeight: FontWeight.bold, fontSize: 13)),
              const SizedBox(width: 10),
              _generatorChip(_rule?['generated_by'] as String?),
              const Spacer(),
              if (_dirty)
                const Text('● Unsaved changes',
                    style: TextStyle(color: Colors.orangeAccent, fontSize: 11))
              else
                const Text('Saved · yara-python validated',
                    style: TextStyle(color: Colors.white38, fontSize: 11)),
            ]),
          ),
          Padding(
            padding: const EdgeInsets.all(16),
            child: TextField(
              controller: _editor,
              readOnly: _saving,
              maxLines: null,
              minLines: 16,
              keyboardType: TextInputType.multiline,
              style: const TextStyle(
                fontFamily: 'monospace',
                fontSize: 13,
                color: Color(0xFFE2E8F0),
                height: 1.6,
              ),
              decoration: const InputDecoration.collapsed(
                  hintText: 'rule name { condition: ... }'),
            ),
          ),
        ],
      ),
    );
  }

  Widget _buildCompileError() {
    return Container(
      width: double.infinity,
      padding: const EdgeInsets.all(12),
      decoration: BoxDecoration(
        color: Colors.red.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(8),
        border: Border.all(color: Colors.red.withValues(alpha: 0.6)),
      ),
      child: Row(crossAxisAlignment: CrossAxisAlignment.start, children: [
        const Icon(Icons.error_outline, color: Colors.redAccent, size: 18),
        const SizedBox(width: 8),
        Expanded(
          child: SelectableText(
            '$_compileError\nNot saved. Fix the rule and try again.',
            style: const TextStyle(
                color: Colors.redAccent, fontSize: 12, fontFamily: 'monospace'),
          ),
        ),
      ]),
    );
  }

  Widget _buildSaveRow() {
    return Row(children: [
      Expanded(
        child: TextField(
          controller: _note,
          maxLength: 500,
          style: const TextStyle(color: Colors.white70, fontSize: 13),
          decoration: InputDecoration(
            isDense: true,
            counterText: '',
            hintText: 'Change note (optional), e.g. "require 2 strings"',
            hintStyle: const TextStyle(color: Colors.white24, fontSize: 13),
            filled: true,
            fillColor: _panel,
            border: OutlineInputBorder(
                borderRadius: BorderRadius.circular(8),
                borderSide: BorderSide.none),
          ),
          onSubmitted: (_) => _save(),
        ),
      ),
      const SizedBox(width: 12),
      if (_dirty) ...[
        TextButton(
          onPressed: _saving
              ? null
              : () => setState(() {
                    _editor.text = _savedText;
                    _compileError = null;
                  }),
          child: const Text('Discard', style: TextStyle(color: Colors.white54)),
        ),
        const SizedBox(width: 8),
      ],
      ElevatedButton.icon(
        onPressed: _dirty && !_saving ? _save : null,
        icon: _saving
            ? const SizedBox(
                width: 14,
                height: 14,
                child: CircularProgressIndicator(strokeWidth: 2, color: _bg))
            : const Icon(Icons.save, size: 16),
        label: const Text('Save & Validate'),
        style: ElevatedButton.styleFrom(
          backgroundColor: _cyan,
          foregroundColor: _bg,
          disabledBackgroundColor: Colors.white12,
          disabledForegroundColor: Colors.white38,
          shape:
              RoundedRectangleBorder(borderRadius: BorderRadius.circular(8)),
        ),
      ),
    ]);
  }

  Widget _buildIndicators() {
    return Column(
      crossAxisAlignment: CrossAxisAlignment.start,
      children: [
        const Text('Extracted Indicators',
            style: TextStyle(
                color: Colors.white, fontWeight: FontWeight.bold, fontSize: 16)),
        const SizedBox(height: 10),
        Wrap(
          spacing: 8,
          runSpacing: 8,
          children: _indicators.map((ind) {
            final color = _indicatorColor(ind['type'] ?? '');
            final value = '${ind['value']}';
            return Container(
              padding: const EdgeInsets.symmetric(horizontal: 10, vertical: 6),
              decoration: BoxDecoration(
                color: color.withValues(alpha: 0.08),
                borderRadius: BorderRadius.circular(6),
                border: Border.all(color: color.withValues(alpha: 0.3)),
              ),
              child: Row(mainAxisSize: MainAxisSize.min, children: [
                Container(
                  width: 6,
                  height: 6,
                  decoration:
                      BoxDecoration(color: color, shape: BoxShape.circle),
                ),
                const SizedBox(width: 6),
                Text('${ind['type']}: ',
                    style: TextStyle(
                        color: color,
                        fontSize: 11,
                        fontWeight: FontWeight.bold)),
                Tooltip(
                  message: value,
                  child: Text(
                    value.length > 30 ? '${value.substring(0, 30)}…' : value,
                    style: const TextStyle(
                        color: Colors.white70,
                        fontSize: 11,
                        fontFamily: 'monospace'),
                  ),
                ),
              ]),
            );
          }).toList(),
        ),
      ],
    );
  }

  Widget _buildReviewPanel() {
    final canApprove =
        !_approved && !_dirty && _isValid && _checklistComplete && !_approving;
    String? approveHint;
    if (_approved) {
      approveHint = 'Edits will send the rule back to draft.';
    } else if (_dirty) {
      approveHint = 'Save your changes before approving.';
    } else if (!_isValid) {
      approveHint = 'The rule must compile before it can be approved.';
    } else if (!_checklistComplete) {
      approveHint = 'Complete all checklist items to approve.';
    }

    return Container(
      padding: const EdgeInsets.all(20),
      decoration: BoxDecoration(
        color: _panel,
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
          const Text('Review the rule before approving for deployment.',
              style: TextStyle(color: Colors.white38, fontSize: 11)),
          const SizedBox(height: 16),

          // Score bar
          Row(children: [
            Text('$_checklistScore/${_checklistItems.length}',
                style: const TextStyle(
                    color: _cyan, fontWeight: FontWeight.bold)),
            const SizedBox(width: 8),
            Expanded(
              child: ClipRRect(
                borderRadius: BorderRadius.circular(4),
                child: LinearProgressIndicator(
                  value: _checklistScore / _checklistItems.length,
                  backgroundColor: Colors.white12,
                  valueColor: AlwaysStoppedAnimation(
                      _checklistComplete ? _green : _cyan),
                  minHeight: 6,
                ),
              ),
            ),
          ]),
          const SizedBox(height: 16),

          ..._checklistItems.map((k) => CheckboxListTile(
                dense: true,
                contentPadding: EdgeInsets.zero,
                title: Text(k,
                    style:
                        const TextStyle(color: Colors.white70, fontSize: 13)),
                value: _checklist[k] ?? false,
                activeColor: _cyan,
                checkColor: _bg,
                // approved rules keep their checklist until edited
                onChanged: _approved
                    ? null
                    : (v) => setState(() => _checklist[k] = v ?? false),
              )),

          const SizedBox(height: 12),
          const Divider(color: Colors.white12),
          const SizedBox(height: 12),

          if (_approved) ...[
            Row(children: [
              const Icon(Icons.verified_user, color: _green, size: 16),
              const SizedBox(width: 8),
              Expanded(
                child: Text(
                  'Approved by ${_rule?['approved_by_name'] ?? 'unknown'}\n'
                  '${_rule?['approved_at'] ?? ''} UTC',
                  style: const TextStyle(color: Colors.white70, fontSize: 12),
                ),
              ),
            ]),
            const SizedBox(height: 12),
          ],

          SizedBox(
            width: double.infinity,
            child: ElevatedButton.icon(
              onPressed: canApprove ? _approve : null,
              icon: _approving
                  ? const SizedBox(
                      width: 14,
                      height: 14,
                      child: CircularProgressIndicator(
                          strokeWidth: 2, color: _bg))
                  : const Icon(Icons.check_circle, size: 16),
              label: Text(_approved ? 'Approved' : 'Approve Rule'),
              style: ElevatedButton.styleFrom(
                backgroundColor: _green,
                foregroundColor: _bg,
                disabledBackgroundColor: Colors.white12,
                disabledForegroundColor: Colors.white38,
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ),
          const SizedBox(height: 10),
          SizedBox(
            width: double.infinity,
            child: OutlinedButton.icon(
              onPressed: _approved && !_exporting ? _export : null,
              icon: const Icon(Icons.download, size: 16),
              label: const Text('Export .yar'),
              style: OutlinedButton.styleFrom(
                foregroundColor: _green,
                side: BorderSide(
                    color: _approved ? _green : Colors.white12),
                shape: RoundedRectangleBorder(
                    borderRadius: BorderRadius.circular(8)),
              ),
            ),
          ),
          if (approveHint != null)
            Padding(
              padding: const EdgeInsets.only(top: 8),
              child: Text(approveHint,
                  style: const TextStyle(color: Colors.white38, fontSize: 11),
                  textAlign: TextAlign.center),
            ),
          if (!_approved)
            const Padding(
              padding: EdgeInsets.only(top: 4),
              child: Text('Only approved rules can be exported.',
                  style: TextStyle(color: Colors.white24, fontSize: 11),
                  textAlign: TextAlign.center),
            ),
        ],
      ),
    );
  }

  // Shows which model wrote the rule, e.g. "gemini:gemini-3.6-flash",
  // "ollama:qwen2.5-coder:3b" or "template". Old rules have no value.
  Widget _generatorChip(String? generatedBy) {
    if (generatedBy == null || generatedBy.isEmpty) {
      return const SizedBox.shrink();
    }
    final sep = generatedBy.indexOf(':');
    final provider = sep == -1 ? generatedBy : generatedBy.substring(0, sep);
    final model = sep == -1 ? '' : generatedBy.substring(sep + 1);

    String label;
    Color color;
    IconData icon;
    switch (provider) {
      case 'gemini':
        // "gemini-3.6-flash" -> "Gemini 3.6 Flash"
        label = model
            .split('-')
            .map((w) => w.isEmpty ? w : w[0].toUpperCase() + w.substring(1))
            .join(' ');
        color = _green;
        icon = Icons.cloud_outlined;
        break;
      case 'ollama':
        label = 'Local: $model';
        color = Colors.purpleAccent;
        icon = Icons.computer;
        break;
      case 'template':
        label = 'Fallback template';
        color = Colors.orangeAccent;
        icon = Icons.warning_amber_rounded;
        break;
      default:
        label = generatedBy;
        color = Colors.white54;
        icon = Icons.help_outline;
    }

    return Tooltip(
      message: provider == 'template'
          ? 'No LLM was available; this rule is a basic template'
          : 'Generated by $generatedBy',
      child: Container(
        padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
        decoration: BoxDecoration(
          color: color.withValues(alpha: 0.1),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: color.withValues(alpha: 0.6)),
        ),
        child: Row(mainAxisSize: MainAxisSize.min, children: [
          Icon(icon, color: color, size: 12),
          const SizedBox(width: 4),
          Text(label,
              style: TextStyle(
                  color: color, fontSize: 11, fontWeight: FontWeight.bold)),
        ]),
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
      case 'api_import':   return _green;
      case 'file':         return Colors.tealAccent;
      default:             return _cyan;
    }
  }
}

// Lists a rule's versions; each can be viewed read-only or restored.
// Pops with a message when a version was restored.
class _VersionHistoryDialog extends StatefulWidget {
  final int ruleId;
  final int currentVersion;
  final bool hasUnsavedChanges;

  const _VersionHistoryDialog({
    required this.ruleId,
    required this.currentVersion,
    required this.hasUnsavedChanges,
  });

  @override
  State<_VersionHistoryDialog> createState() => _VersionHistoryDialogState();
}

class _VersionHistoryDialogState extends State<_VersionHistoryDialog> {
  List<dynamic>? _versions;
  String? _error;
  bool _busy = false;

  @override
  void initState() {
    super.initState();
    ApiService.getRuleVersions(widget.ruleId).then(
      (v) => setState(() => _versions = v),
      onError: (e) => setState(() => _error = '$e'),
    );
  }

  Future<void> _view(int version) async {
    setState(() => _busy = true);
    try {
      final v = await ApiService.getRuleVersion(widget.ruleId, version);
      if (!mounted) return;
      await showDialog<void>(
        context: context,
        builder: (ctx) => AlertDialog(
          backgroundColor: _panel,
          title: Text('Version $version (read-only)'),
          content: SizedBox(
            width: 640,
            child: SingleChildScrollView(
              child: SelectableText(
                v['rule_text'] ?? '',
                style: const TextStyle(
                    fontFamily: 'monospace',
                    fontSize: 12,
                    color: Color(0xFFE2E8F0),
                    height: 1.5),
              ),
            ),
          ),
          actions: [
            TextButton(
                onPressed: () => Navigator.pop(ctx),
                child: const Text('Close')),
          ],
        ),
      );
    } catch (e) {
      if (mounted) setState(() => _error = '$e');
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  Future<void> _restore(int version) async {
    final ok = await showDialog<bool>(
      context: context,
      builder: (ctx) => AlertDialog(
        backgroundColor: _panel,
        title: Text('Restore version $version?'),
        content: Text(
          'Version $version will be copied into a new version '
          '${widget.currentVersion + 1}. No history is deleted, and the rule '
          'goes back to draft until it is approved again.'
          '${widget.hasUnsavedChanges ? '\n\nYour unsaved edits will be lost.' : ''}',
        ),
        actions: [
          TextButton(
              onPressed: () => Navigator.pop(ctx, false),
              child: const Text('Cancel')),
          TextButton(
              onPressed: () => Navigator.pop(ctx, true),
              child: const Text('Restore')),
        ],
      ),
    );
    if (ok != true || !mounted) return;
    setState(() => _busy = true);
    try {
      final r = await ApiService.restoreRuleVersion(widget.ruleId, version);
      if (mounted) Navigator.pop(context, r['message'] ?? 'Version restored');
    } catch (e) {
      if (mounted) {
        setState(() {
          _error = '$e';
          _busy = false;
        });
      }
    }
  }

  @override
  Widget build(BuildContext context) {
    return AlertDialog(
      backgroundColor: _panel,
      title: const Row(children: [
        Icon(Icons.history, color: _cyan),
        SizedBox(width: 8),
        Text('Version History'),
      ]),
      content: SizedBox(
        width: 640,
        height: 420,
        child: Column(children: [
          if (_error != null)
            Padding(
              padding: const EdgeInsets.only(bottom: 8),
              child: Text(_error!,
                  style: const TextStyle(color: Colors.redAccent)),
            ),
          if (_busy) const LinearProgressIndicator(color: _cyan),
          Expanded(
            child: _versions == null
                ? (_error == null
                    ? const Center(
                        child: CircularProgressIndicator(color: _cyan))
                    : const SizedBox.shrink())
                : ListView.separated(
                    itemCount: _versions!.length,
                    separatorBuilder: (_, __) =>
                        const Divider(color: Colors.white12, height: 1),
                    itemBuilder: (_, i) => _versionTile(_versions![i]),
                  ),
          ),
        ]),
      ),
      actions: [
        TextButton(
            onPressed: () => Navigator.pop(context),
            child: const Text('Close')),
      ],
    );
  }

  Widget _versionTile(Map<String, dynamic> v) {
    final version = v['version'] as int;
    final isCurrent = version == widget.currentVersion;
    final valid = v['is_valid'] == 1;
    final note = v['change_note'] as String?;
    return ListTile(
      contentPadding: const EdgeInsets.symmetric(horizontal: 4),
      leading: CircleAvatar(
        radius: 18,
        backgroundColor: (isCurrent ? _green : _cyan).withValues(alpha: 0.15),
        child: Text('v$version',
            style: TextStyle(
                color: isCurrent ? _green : _cyan,
                fontSize: 12,
                fontWeight: FontWeight.bold)),
      ),
      title: Row(children: [
        Text(v['source'] ?? '',
            style: const TextStyle(color: Colors.white, fontSize: 14)),
        if (isCurrent)
          const Padding(
            padding: EdgeInsets.only(left: 8),
            child: Text('current',
                style: TextStyle(color: _green, fontSize: 11)),
          ),
        if (!valid)
          const Padding(
            padding: EdgeInsets.only(left: 8),
            child: Text('does not compile',
                style: TextStyle(color: Colors.redAccent, fontSize: 11)),
          ),
      ]),
      subtitle: Text(
        '${v['created_by_name'] ?? 'unknown'} · ${v['created'] ?? ''} UTC'
        '${note != null && note.isNotEmpty ? '\n$note' : ''}',
        style: const TextStyle(color: Colors.white54, fontSize: 12),
      ),
      isThreeLine: note != null && note.isNotEmpty,
      trailing: Row(mainAxisSize: MainAxisSize.min, children: [
        IconButton(
          tooltip: 'View',
          icon: const Icon(Icons.visibility, color: Colors.white54, size: 18),
          onPressed: _busy ? null : () => _view(version),
        ),
        IconButton(
          tooltip: isCurrent ? 'This is the current version' : 'Restore',
          icon: const Icon(Icons.restore, size: 18),
          color: _cyan,
          onPressed: _busy || isCurrent ? null : () => _restore(version),
        ),
      ]),
    );
  }
}
