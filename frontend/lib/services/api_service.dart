import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

// An error from the backend, carrying its "detail" message and HTTP status
// (e.g. 422 when an edited rule doesn't compile).
class ApiException implements Exception {
  final String message;
  final int statusCode;
  ApiException(this.message, this.statusCode);

  @override
  String toString() => message;
}

class ApiService {
  static const String baseUrl = 'http://127.0.0.1:8000';

  // Builds an exception from the server's "detail" message, so screens can
  // show e.g. "Unsupported file type" instead of raw JSON.
  static ApiException _error(http.Response response, String fallback) {
    try {
      final detail = jsonDecode(response.body)['detail'];
      if (detail is String && detail.isNotEmpty) {
        return ApiException(detail, response.statusCode);
      }
      if (detail is List && detail.isNotEmpty) {
        // FastAPI request validation errors
        return ApiException(
            detail.map((d) => d['msg'] ?? '$d').join('; '), response.statusCode);
      }
    } catch (_) {}
    return ApiException(
        '$fallback (HTTP ${response.statusCode})', response.statusCode);
  }

  static Future<Map<String, String>> _authHeaders({bool json = false}) async {
    final token = await getToken();
    return {
      'Authorization': 'Bearer $token',
      if (json) 'Content-Type': 'application/json',
    };
  }

  static Future<String?> getToken() async {
    final prefs = await SharedPreferences.getInstance();
    return prefs.getString('token');
  }

  static Future<void> saveToken(String token) async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.setString('token', token);
  }

  static Future<void> clearToken() async {
    final prefs = await SharedPreferences.getInstance();
    await prefs.remove('token');
    await prefs.remove('username');
    await prefs.remove('role');
  }

  static Future<Map<String, dynamic>> login(
      String username, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/auth/login'),
      headers: {'Content-Type': 'application/x-www-form-urlencoded'},
      body: {'username': username, 'password': password},
    );
    if (response.statusCode == 200) {
      final data = jsonDecode(response.body);
      await saveToken(data['access_token']);
      final prefs = await SharedPreferences.getInstance();
      await prefs.setString('username', data['username']);
      await prefs.setString('role', data['role']);
      return data;
    }
    throw _error(response, 'Login failed');
  }

  static Future<Map<String, dynamic>> register(
      String username, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/auth/register'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'username': username, 'password': password}),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Register failed');
  }

  static Future<Map<String, dynamic>> uploadArtifact(
      String filename, Uint8List bytes) async {
    final token = await getToken();
    final request = http.MultipartRequest(
      'POST',
      Uri.parse('$baseUrl/artifacts/upload'),
    );
    request.headers['Authorization'] = 'Bearer $token';
    request.files.add(
      http.MultipartFile.fromBytes('file', bytes, filename: filename),
    );
    final streamed = await request.send();
    final response = await http.Response.fromStream(streamed);
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Upload failed');
  }

  // Filters are optional: q (filename search), status ('draft'/'approved'),
  // generatedBy ('gemini'/'ollama'/'template'), dateFrom/dateTo (YYYY-MM-DD).
  static Future<List<dynamic>> getArtifacts({
    String? q,
    String? status,
    String? generatedBy,
    String? dateFrom,
    String? dateTo,
  }) async {
    final params = {
      if (q != null && q.isNotEmpty) 'q': q,
      if (status != null) 'status': status,
      if (generatedBy != null) 'generated_by': generatedBy,
      if (dateFrom != null) 'date_from': dateFrom,
      if (dateTo != null) 'date_to': dateTo,
    };
    final response = await http.get(
      Uri.parse('$baseUrl/artifacts').replace(queryParameters: params),
      headers: await _authHeaders(),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to load artifacts');
  }

  static Future<Map<String, dynamic>> getArtifactRule(int artifactId) async {
    final response = await http.get(
      Uri.parse('$baseUrl/artifacts/$artifactId/rule'),
      headers: await _authHeaders(),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to load rule');
  }

  // Saves an edit as a new version. Throws ApiException with statusCode 422
  // (and the YARA compiler error as message) if the rule doesn't compile.
  static Future<Map<String, dynamic>> editRule(
      int ruleId, String ruleText, String? changeNote) async {
    final response = await http.put(
      Uri.parse('$baseUrl/rules/$ruleId'),
      headers: await _authHeaders(json: true),
      body: jsonEncode({'rule_text': ruleText, 'change_note': changeNote}),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to save rule');
  }

  static Future<List<dynamic>> getRuleVersions(int ruleId) async {
    final response = await http.get(
      Uri.parse('$baseUrl/rules/$ruleId/versions'),
      headers: await _authHeaders(),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to load versions');
  }

  static Future<Map<String, dynamic>> getRuleVersion(
      int ruleId, int version) async {
    final response = await http.get(
      Uri.parse('$baseUrl/rules/$ruleId/versions/$version'),
      headers: await _authHeaders(),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to load version');
  }

  static Future<Map<String, dynamic>> restoreRuleVersion(
      int ruleId, int version) async {
    final response = await http.post(
      Uri.parse('$baseUrl/rules/$ruleId/versions/$version/restore'),
      headers: await _authHeaders(),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to restore version');
  }

  static Future<Map<String, dynamic>> approveRule(
      int ruleId, Map<String, bool> checklist) async {
    final response = await http.post(
      Uri.parse('$baseUrl/rules/$ruleId/approve'),
      headers: await _authHeaders(json: true),
      body: jsonEncode({'checklist': checklist}),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to approve rule');
  }

  // Returns the .yar file name (from Content-Disposition) and its bytes.
  static Future<({String filename, Uint8List bytes})> exportRule(
      int ruleId) async {
    final response = await http.get(
      Uri.parse('$baseUrl/rules/$ruleId/export'),
      headers: await _authHeaders(),
    );
    if (response.statusCode != 200) {
      throw _error(response, 'Failed to export rule');
    }
    final disposition = response.headers['content-disposition'] ?? '';
    final match = RegExp(r'filename="?([^";]+)"?').firstMatch(disposition);
    return (
      filename: match?.group(1) ?? 'smartyara_rule_$ruleId.yar',
      bytes: response.bodyBytes,
    );
  }

  static Future<Map<String, dynamic>> getDashboardStats() async {
    final response = await http.get(
      Uri.parse('$baseUrl/dashboard/stats'),
      headers: await _authHeaders(),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw _error(response, 'Failed to load stats');
  }
}
