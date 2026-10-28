import 'dart:async';
import 'package:flutter/material.dart';
import 'package:intl/intl.dart';
import '../services/api_service.dart';
import '../screens/rule_review_screen.dart';

const _bg = Color(0xFF0D1B2A);
const _panel = Color(0xFF112240);
const _cyan = Color(0xFF00D4FF);
const _green = Color(0xFF00FF88);

// All of the analyst's artifacts and rules, with search and filters.
class HistoryScreen extends StatefulWidget {
  const HistoryScreen({super.key});
  @override
  State<HistoryScreen> createState() => _HistoryScreenState();
}

class _HistoryScreenState extends State<HistoryScreen> {
  final _search = TextEditingController();
  Timer? _debounce;
  String? _status;        // null = all, 'draft', 'approved'
  String? _generator;     // null = all, 'gemini', 'ollama', 'template'
  DateTimeRange? _dates;

  List<dynamic> _rows = [];
  bool _loading = true;
  String? _error;

  static final _apiDate = DateFormat('yyyy-MM-dd');
  static final _shortDate = DateFormat('d MMM yyyy');

  @override
  void initState() {
    super.initState();
    _load();
  }

  @override
  void dispose() {
    _debounce?.cancel();
    _search.dispose();
    super.dispose();
  }

  Future<void> _load() async {
    setState(() {
      _loading = true;
      _error = null;
    });
    try {
      final rows = await ApiService.getArtifacts(
        q: _search.text.trim(),
        status: _status,
        generatedBy: _generator,
        dateFrom: _dates == null ? null : _apiDate.format(_dates!.start),
        dateTo: _dates == null ? null : _apiDate.format(_dates!.end),
      );
      if (!mounted) return;
      setState(() {
        _rows = rows;
        _loading = false;
      });
    } catch (e) {
      if (!mounted) return;
      setState(() {
        _error = '$e';
        _loading = false;
      });
    }
  }

  void _onSearchChanged(String _) {
    _debounce?.cancel();
    _debounce = Timer(const Duration(milliseconds: 400), _load);
  }

  Future<void> _pickDates() async {
    final now = DateTime.now();
    final picked = await showDateRangePicker(
      context: context,
      firstDate: DateTime(2020),
      lastDate: DateTime(now.year, now.month, now.day),
      initialDateRange: _dates,
    );
    if (picked != null) {
      setState(() => _dates = picked);
      _load();
    }
  }

  void _clearFilters() {
    _search.clear();
    setState(() {
      _status = null;
      _generator = null;
      _dates = null;
    });
    _load();
  }

  bool get _hasFilters =>
      _search.text.isNotEmpty ||
      _status != null ||
      _generator != null ||
      _dates != null;

  Future<void> _open(Map<String, dynamic> a) async {
    await Navigator.push(
      context,
      MaterialPageRoute(
        builder: (_) => RuleReviewScreen(
            artifactId: a['id'], filename: a['filename'] ?? ''),
      ),
    );
    _load();   // status or version may have changed
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: _bg,
      appBar: AppBar(
        backgroundColor: _panel,
        title: const Text('Artifact & Rule History',
            style: TextStyle(color: Colors.white)),
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: Padding(
        padding: const EdgeInsets.all(24),
        child: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            _buildFilters(),
            const SizedBox(height: 16),
            Text(
              _loading ? 'Loading…' : '${_rows.length} artifact(s)',
              style: const TextStyle(color: Colors.white54, fontSize: 13),
            ),
            const SizedBox(height: 8),
            Expanded(child: _buildResults()),
          ],
        ),
      ),
    );
  }

  Widget _buildFilters() {
    return Wrap(
      spacing: 12,
      runSpacing: 12,
      crossAxisAlignment: WrapCrossAlignment.center,
      children: [
        SizedBox(
          width: 280,
          child: TextField(
            controller: _search,
            onChanged: _onSearchChanged,
            style: const TextStyle(color: Colors.white, fontSize: 14),
            decoration: InputDecoration(
              isDense: true,
              prefixIcon: const Icon(Icons.search, color: Colors.white38),
              hintText: 'Search filename',
              hintStyle: const TextStyle(color: Colors.white38),
              filled: true,
              fillColor: _panel,
              border: OutlineInputBorder(
                  borderRadius: BorderRadius.circular(8),
                  borderSide: BorderSide.none),
            ),
          ),
        ),
        _dropdown<String?>(
          value: _status,
          items: const {null: 'All statuses', 'draft': 'Draft', 'approved': 'Approved'},
          onChanged: (v) {
            setState(() => _status = v);
            _load();
          },
        ),
        _dropdown<String?>(
          value: _generator,
          items: const {
            null: 'All generators',
            'gemini': 'Gemini',
            'ollama': 'Local (Ollama)',
            'template': 'Fallback template',
          },
          onChanged: (v) {
            setState(() => _generator = v);
            _load();
          },
        ),
        OutlinedButton.icon(
          onPressed: _pickDates,
          icon: const Icon(Icons.date_range, size: 16),
          label: Text(_dates == null
              ? 'Any date'
              : '${_shortDate.format(_dates!.start)} – ${_shortDate.format(_dates!.end)}'),
          style: OutlinedButton.styleFrom(
            foregroundColor: _cyan,
            side: BorderSide(color: _cyan.withValues(alpha: 0.4)),
            padding: const EdgeInsets.symmetric(horizontal: 14, vertical: 14),
          ),
        ),
        if (_hasFilters)
          TextButton.icon(
            onPressed: _clearFilters,
            icon: const Icon(Icons.clear, size: 16, color: Colors.white54),
            label: const Text('Clear filters',
                style: TextStyle(color: Colors.white54)),
          ),
      ],
    );
  }

  Widget _dropdown<T>({
    required T value,
    required Map<T, String> items,
    required ValueChanged<T> onChanged,
  }) {
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 12),
      decoration: BoxDecoration(
        color: _panel,
        borderRadius: BorderRadius.circular(8),
      ),
      child: DropdownButtonHideUnderline(
        child: DropdownButton<T>(
          value: value,
          dropdownColor: _panel,
          style: const TextStyle(color: Colors.white, fontSize: 14),
          items: items.entries
              .map((e) => DropdownMenuItem<T>(value: e.key, child: Text(e.value)))
              .toList(),
          onChanged: (v) => onChanged(v as T),
        ),
      ),
    );
  }

  Widget _buildResults() {
    if (_loading) {
      return const Center(child: CircularProgressIndicator(color: _cyan));
    }
    if (_error != null) {
      return Center(
          child: Text(_error!, style: const TextStyle(color: Colors.redAccent)));
    }
    if (_rows.isEmpty) {
      return Center(
        child: Text(
          _hasFilters ? 'No artifacts match these filters' : 'No artifacts yet',
          style: const TextStyle(color: Colors.white38, fontSize: 16),
        ),
      );
    }
    return Container(
      decoration: BoxDecoration(
        color: _panel,
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: Colors.white12),
      ),
      child: SingleChildScrollView(
        child: SizedBox(
          width: double.infinity,
          child: DataTable(
            showCheckboxColumn: false,
            headingTextStyle: const TextStyle(
                color: Colors.white54, fontWeight: FontWeight.bold, fontSize: 12),
            dataTextStyle: const TextStyle(color: Colors.white70, fontSize: 13),
            columns: const [
              DataColumn(label: Text('FILENAME')),
              DataColumn(label: Text('UPLOADED (UTC)')),
              DataColumn(label: Text('STATUS')),
              DataColumn(label: Text('GENERATED BY')),
              DataColumn(label: Text('VERSION'), numeric: true),
              DataColumn(label: Text('INDICATORS'), numeric: true),
            ],
            rows: _rows.map((a) {
              final row = Map<String, dynamic>.from(a);
              return DataRow(
                onSelectChanged: (_) => _open(row),
                cells: [
                  DataCell(Text(row['filename'] ?? '',
                      style: const TextStyle(
                          color: Colors.white, fontWeight: FontWeight.w600))),
                  DataCell(Text(row['uploaded'] ?? '')),
                  DataCell(_statusBadge(row['status'] as String?)),
                  DataCell(Text(_generatorLabel(row['generated_by'] as String?))),
                  DataCell(Text(
                      row['current_version'] == null ? '–' : 'v${row['current_version']}')),
                  DataCell(Text('${row['indicator_count'] ?? 0}')),
                ],
              );
            }).toList(),
          ),
        ),
      ),
    );
  }

  Widget _statusBadge(String? status) {
    final approved = status == 'approved';
    final color = status == null
        ? Colors.white38
        : approved
            ? _green
            : Colors.amberAccent;
    return Container(
      padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 3),
      decoration: BoxDecoration(
        color: color.withValues(alpha: 0.1),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: color.withValues(alpha: 0.6)),
      ),
      child: Text(
        status == null ? 'No rule' : (approved ? 'Approved' : 'Draft'),
        style: TextStyle(color: color, fontSize: 11, fontWeight: FontWeight.bold),
      ),
    );
  }

  String _generatorLabel(String? generatedBy) {
    if (generatedBy == null || generatedBy.isEmpty) return '–';
    if (generatedBy == 'template') return 'Fallback template';
    final sep = generatedBy.indexOf(':');
    if (sep == -1) return generatedBy;
    final provider = generatedBy.substring(0, sep);
    final model = generatedBy.substring(sep + 1);
    return provider == 'ollama' ? 'Local: $model' : model;
  }
}
