import 'package:flutter/material.dart';
import 'package:shared_preferences/shared_preferences.dart';
import '../services/api_service.dart';
import '../screens/login_screen.dart';
import '../screens/upload_screen.dart';
import '../screens/rule_review_screen.dart';

class DashboardScreen extends StatefulWidget {
  const DashboardScreen({super.key});
  @override
  State<DashboardScreen> createState() => _DashboardScreenState();
}

class _DashboardScreenState extends State<DashboardScreen> {
  Map<String, dynamic>? _stats;
  List<dynamic> _artifacts = [];
  bool _loading = true;
  String _username = '';

  @override
  void initState() {
    super.initState();
    _load();
  }

  Future<void> _load() async {
    setState(() => _loading = true);
    try {
      final prefs = await SharedPreferences.getInstance();
      _username = prefs.getString('username') ?? 'Analyst';
      final stats = await ApiService.getDashboardStats();
      final artifacts = await ApiService.getArtifacts();
      setState(() {
        _stats = stats;
        _artifacts = artifacts;
        _loading = false;
      });
    } catch (e) {
      setState(() => _loading = false);
    }
  }

  Future<void> _logout() async {
    await ApiService.clearToken();
    if (mounted) {
      Navigator.pushReplacement(context,
          MaterialPageRoute(builder: (_) => const LoginScreen()));
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF112240),
        elevation: 0,
        title: Row(children: [
          const Icon(Icons.security, color: Color(0xFF00D4FF), size: 24),
          const SizedBox(width: 10),
          const Text('SmartYARA',
              style: TextStyle(color: Color(0xFF00D4FF),
                  fontWeight: FontWeight.bold, fontSize: 20)),
          const SizedBox(width: 8),
          Container(
            padding: const EdgeInsets.symmetric(horizontal: 8, vertical: 2),
            decoration: BoxDecoration(
              color: const Color(0xFF00D4FF).withOpacity(0.1),
              borderRadius: BorderRadius.circular(4),
              border: Border.all(color: const Color(0xFF00D4FF).withOpacity(0.3)),
            ),
            child: const Text('ANALYST DASHBOARD',
                style: TextStyle(color: Color(0xFF00D4FF),
                    fontSize: 10, letterSpacing: 1.5)),
          ),
        ]),
        actions: [
          Padding(
            padding: const EdgeInsets.only(right: 8),
            child: Row(children: [
              const Icon(Icons.person, color: Colors.white54, size: 18),
              const SizedBox(width: 6),
              Text(_username,
                  style: const TextStyle(color: Colors.white70, fontSize: 14)),
            ]),
          ),
          IconButton(
            icon: const Icon(Icons.logout, color: Colors.white54),
            tooltip: 'Logout',
            onPressed: _logout,
          ),
        ],
      ),
      floatingActionButton: FloatingActionButton.extended(
        onPressed: () async {
          await Navigator.push(context,
              MaterialPageRoute(builder: (_) => const UploadScreen()));
          _load();
        },
        backgroundColor: const Color(0xFF00D4FF),
        foregroundColor: const Color(0xFF0D1B2A),
        icon: const Icon(Icons.upload_file),
        label: const Text('Upload Artifact',
            style: TextStyle(fontWeight: FontWeight.bold)),
      ),
      body: _loading
          ? const Center(child: CircularProgressIndicator(
              color: Color(0xFF00D4FF)))
          : RefreshIndicator(
              onRefresh: _load,
              child: SingleChildScrollView(
                physics: const AlwaysScrollableScrollPhysics(),
                padding: const EdgeInsets.all(24),
                child: Column(
                  crossAxisAlignment: CrossAxisAlignment.start,
                  children: [
                    _buildStatsRow(),
                    const SizedBox(height: 32),
                    const Text('Recent Artifacts',
                        style: TextStyle(fontSize: 18,
                            fontWeight: FontWeight.bold, color: Colors.white)),
                    const SizedBox(height: 16),
                    _buildArtifactList(),
                  ],
                ),
              ),
            ),
    );
  }

  Widget _buildStatsRow() {
    final s = _stats ?? {};
    return GridView.count(
      crossAxisCount: 4,
      shrinkWrap: true,
      physics: const NeverScrollableScrollPhysics(),
      crossAxisSpacing: 16,
      mainAxisSpacing: 16,
      childAspectRatio: 1.6,
      children: [
        _statCard('Artifacts', '${s['total_artifacts'] ?? 0}',
            Icons.folder_open, const Color(0xFF00D4FF)),
        _statCard('Rules Generated', '${s['total_rules'] ?? 0}',
            Icons.code, const Color(0xFF00FF88)),
        _statCard('Valid Rules', '${s['valid_rules'] ?? 0}',
            Icons.verified, const Color(0xFF00D4FF)),
        _statCard('Indicators', '${s['total_indicators'] ?? 0}',
            Icons.label, Colors.orangeAccent),
      ],
    );
  }

  Widget _statCard(String label, String value, IconData icon, Color color) {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF112240),
        borderRadius: BorderRadius.circular(12),
        border: Border.all(color: color.withOpacity(0.2)),
      ),
      child: Column(
        crossAxisAlignment: CrossAxisAlignment.start,
        mainAxisAlignment: MainAxisAlignment.spaceBetween,
        children: [
          Icon(icon, color: color, size: 22),
          Column(
            crossAxisAlignment: CrossAxisAlignment.start,
            children: [
              Text(value,
                  style: TextStyle(fontSize: 28,
                      fontWeight: FontWeight.bold, color: color)),
              Text(label,
                  style: const TextStyle(fontSize: 12, color: Colors.white54)),
            ],
          ),
        ],
      ),
    );
  }

  Widget _buildArtifactList() {
    if (_artifacts.isEmpty) {
      return Container(
        padding: const EdgeInsets.all(40),
        decoration: BoxDecoration(
          color: const Color(0xFF112240),
          borderRadius: BorderRadius.circular(12),
          border: Border.all(color: Colors.white12),
        ),
        child: const Center(
          child: Column(mainAxisSize: MainAxisSize.min, children: [
            Icon(Icons.inbox, color: Colors.white24, size: 48),
            SizedBox(height: 12),
            Text('No artifacts yet',
                style: TextStyle(color: Colors.white38, fontSize: 16)),
            Text('Upload a malware artifact to generate a YARA rule',
                style: TextStyle(color: Colors.white24, fontSize: 13)),
          ]),
        ),
      );
    }

    return Column(
      children: _artifacts.map((a) => _artifactTile(a)).toList(),
    );
  }

  Widget _artifactTile(Map<String, dynamic> a) {
    return Container(
      margin: const EdgeInsets.only(bottom: 10),
      decoration: BoxDecoration(
        color: const Color(0xFF112240),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: Colors.white12),
      ),
      child: ListTile(
        contentPadding: const EdgeInsets.symmetric(horizontal: 16, vertical: 8),
        leading: Container(
          width: 42, height: 42,
          decoration: BoxDecoration(
            color: const Color(0xFF00D4FF).withOpacity(0.1),
            borderRadius: BorderRadius.circular(8),
          ),
          child: const Icon(Icons.insert_drive_file,
              color: Color(0xFF00D4FF), size: 22),
        ),
        title: Text(a['filename'] ?? '',
            style: const TextStyle(color: Colors.white,
                fontWeight: FontWeight.w600)),
        subtitle: Column(
          crossAxisAlignment: CrossAxisAlignment.start,
          children: [
            const SizedBox(height: 4),
            Text('${a['indicator_count'] ?? 0} indicators extracted',
                style: const TextStyle(color: Colors.white54, fontSize: 12)),
            Text(
              'SHA-256: ${(a['filehash'] ?? '').toString().substring(0, 16)}...',
              style: const TextStyle(
                  color: Colors.white38, fontSize: 11,
                  fontFamily: 'monospace'),
            ),
          ],
        ),
        trailing: ElevatedButton.icon(
          onPressed: () {
            Navigator.push(context,
                MaterialPageRoute(
                    builder: (_) =>
                        RuleReviewScreen(artifactId: a['id'],
                            filename: a['filename'])));
          },
          icon: const Icon(Icons.code, size: 16),
          label: const Text('View Rule'),
          style: ElevatedButton.styleFrom(
            backgroundColor: const Color(0xFF00D4FF).withOpacity(0.15),
            foregroundColor: const Color(0xFF00D4FF),
            side: const BorderSide(color: Color(0xFF00D4FF), width: 1),
            shape: RoundedRectangleBorder(
                borderRadius: BorderRadius.circular(8)),
          ),
        ),
      ),
    );
  }
}
