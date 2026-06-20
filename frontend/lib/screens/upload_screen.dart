import 'package:flutter/material.dart';
import 'package:file_picker/file_picker.dart';
import '../services/api_service.dart';
import '../screens/rule_review_screen.dart';

class UploadScreen extends StatefulWidget {
  const UploadScreen({super.key});
  @override
  State<UploadScreen> createState() => _UploadScreenState();
}

class _UploadScreenState extends State<UploadScreen> {
  bool _uploading = false;
  String _status = '';
  String? _selectedFile;

  Future<void> _pick() async {
    final result = await FilePicker.platform.pickFiles(
      type: FileType.custom,
      allowedExtensions: ['txt', 'log', 'json', 'csv', 'xml', 'md', 'yar', 'yara'],
      withData: true,
    );
    if (result == null || result.files.isEmpty) return;
    final file = result.files.first;
    setState(() {
      _selectedFile = file.name;
      _uploading = true;
      _status = 'Uploading artifact...';
    });

    try {
      setState(() => _status = '📤 Uploading file...');
      await Future.delayed(const Duration(milliseconds: 300));

      setState(() => _status = '🔍 Extracting indicators with NLP...');
      await Future.delayed(const Duration(milliseconds: 500));

      setState(() => _status = '🤖 Generating YARA rule with LLM...');
      final result2 = await ApiService.uploadArtifact(
          file.name, file.bytes!);

      setState(() => _status = '✅ Done! Redirecting to rule review...');
      await Future.delayed(const Duration(milliseconds: 600));

      if (mounted) {
        Navigator.pushReplacement(
          context,
          MaterialPageRoute(
            builder: (_) => RuleReviewScreen(
              artifactId: result2['artifact_id'],
              filename: result2['filename'],
              uploadResult: result2,
            ),
          ),
        );
      }
    } catch (e) {
      setState(() {
        _uploading = false;
        _status = '❌ Error: ${e.toString().replaceFirst("Exception: ", "")}';
      });
    }
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      backgroundColor: const Color(0xFF0D1B2A),
      appBar: AppBar(
        backgroundColor: const Color(0xFF112240),
        title: const Text('Upload Malware Artifact',
            style: TextStyle(color: Colors.white)),
        iconTheme: const IconThemeData(color: Colors.white),
      ),
      body: Center(
        child: Container(
          width: 520,
          padding: const EdgeInsets.all(40),
          decoration: BoxDecoration(
            color: const Color(0xFF112240),
            borderRadius: BorderRadius.circular(16),
            border: Border.all(color: Colors.white12),
          ),
          child: Column(
            mainAxisSize: MainAxisSize.min,
            children: [
              // Drop zone
              GestureDetector(
                onTap: _uploading ? null : _pick,
                child: AnimatedContainer(
                  duration: const Duration(milliseconds: 200),
                  width: double.infinity,
                  padding: const EdgeInsets.all(40),
                  decoration: BoxDecoration(
                    color: _uploading
                        ? const Color(0xFF00D4FF).withOpacity(0.05)
                        : const Color(0xFF00D4FF).withOpacity(0.03),
                    borderRadius: BorderRadius.circular(12),
                    border: Border.all(
                      color: _uploading
                          ? const Color(0xFF00D4FF).withOpacity(0.6)
                          : const Color(0xFF00D4FF).withOpacity(0.25),
                      width: 2,
                      strokeAlign: BorderSide.strokeAlignInside,
                    ),
                  ),
                  child: Column(
                    children: [
                      Icon(
                        _uploading ? Icons.hourglass_top : Icons.cloud_upload,
                        color: const Color(0xFF00D4FF),
                        size: 48,
                      ),
                      const SizedBox(height: 16),
                      Text(
                        _uploading
                            ? 'Processing...'
                            : 'Click to select artifact file',
                        style: const TextStyle(
                            color: Colors.white, fontSize: 16,
                            fontWeight: FontWeight.w600),
                      ),
                      const SizedBox(height: 8),
                      const Text(
                        'Supported: .txt .log .json .csv .xml .md .yar .yara',
                        style: TextStyle(color: Colors.white38, fontSize: 12),
                      ),
                    ],
                  ),
                ),
              ),

              if (_selectedFile != null) ...[
                const SizedBox(height: 20),
                Container(
                  padding: const EdgeInsets.all(12),
                  decoration: BoxDecoration(
                    color: const Color(0xFF0D1B2A),
                    borderRadius: BorderRadius.circular(8),
                  ),
                  child: Row(children: [
                    const Icon(Icons.insert_drive_file,
                        color: Color(0xFF00D4FF), size: 18),
                    const SizedBox(width: 10),
                    Expanded(
                      child: Text(_selectedFile!,
                          style: const TextStyle(
                              color: Colors.white70, fontSize: 13)),
                    ),
                  ]),
                ),
              ],

              if (_status.isNotEmpty) ...[
                const SizedBox(height: 20),
                _buildPipeline(),
              ],

              const SizedBox(height: 32),
              const Divider(color: Colors.white12),
              const SizedBox(height: 16),
              const Text('SmartYARA Pipeline',
                  style: TextStyle(color: Colors.white38,
                      fontSize: 12, fontWeight: FontWeight.bold,
                      letterSpacing: 1.2)),
              const SizedBox(height: 12),
              Row(
                mainAxisAlignment: MainAxisAlignment.spaceEvenly,
                children: [
                  _pipeStep(Icons.upload_file, 'Upload'),
                  const Icon(Icons.arrow_forward,
                      color: Colors.white24, size: 14),
                  _pipeStep(Icons.search, 'NLP Extract'),
                  const Icon(Icons.arrow_forward,
                      color: Colors.white24, size: 14),
                  _pipeStep(Icons.smart_toy, 'LLM Generate'),
                  const Icon(Icons.arrow_forward,
                      color: Colors.white24, size: 14),
                  _pipeStep(Icons.verified, 'Validate'),
                  const Icon(Icons.arrow_forward,
                      color: Colors.white24, size: 14),
                  _pipeStep(Icons.rate_review, 'Review'),
                ],
              ),
            ],
          ),
        ),
      ),
    );
  }

  Widget _buildPipeline() {
    return Container(
      padding: const EdgeInsets.all(16),
      decoration: BoxDecoration(
        color: const Color(0xFF0D1B2A),
        borderRadius: BorderRadius.circular(10),
        border: Border.all(color: const Color(0xFF00D4FF).withOpacity(0.2)),
      ),
      child: Row(children: [
        if (_uploading)
          const SizedBox(
            width: 18, height: 18,
            child: CircularProgressIndicator(
                strokeWidth: 2, color: Color(0xFF00D4FF)),
          )
        else
          const Icon(Icons.check_circle, color: Color(0xFF00FF88), size: 18),
        const SizedBox(width: 12),
        Expanded(
          child: Text(_status,
              style: const TextStyle(color: Colors.white70, fontSize: 14)),
        ),
      ]),
    );
  }

  Widget _pipeStep(IconData icon, String label) {
    return Column(mainAxisSize: MainAxisSize.min, children: [
      Icon(icon, color: const Color(0xFF00D4FF).withOpacity(0.6), size: 18),
      const SizedBox(height: 4),
      Text(label,
          style: const TextStyle(color: Colors.white38, fontSize: 9,
              letterSpacing: 0.5)),
    ]);
  }
}
