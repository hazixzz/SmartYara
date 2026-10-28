import 'dart:convert';
import 'dart:typed_data';
import 'package:http/http.dart' as http;
import 'package:shared_preferences/shared_preferences.dart';

class ApiService {
  static const String baseUrl = 'http://127.0.0.1:8000';

  // Builds an exception from the server's "detail" message, so screens can
  // show e.g. "Unsupported file type" instead of raw JSON.
  static Exception _error(http.Response response, String fallback) {
    try {
      final detail = jsonDecode(response.body)['detail'];
      if (detail is String && detail.isNotEmpty) return Exception(detail);
      if (detail is List && detail.isNotEmpty) {
        // FastAPI request validation errors
        return Exception(detail.map((d) => d['msg'] ?? '$d').join('; '));
      }
    } catch (_) {}
    return Exception('$fallback (HTTP ${response.statusCode})');
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
    throw Exception(jsonDecode(response.body)['detail'] ?? 'Login failed');
  }

  static Future<Map<String, dynamic>> register(
      String username, String password) async {
    final response = await http.post(
      Uri.parse('$baseUrl/auth/register'),
      headers: {'Content-Type': 'application/json'},
      body: jsonEncode({'username': username, 'password': password}),
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw Exception(jsonDecode(response.body)['detail'] ?? 'Register failed');
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

  static Future<List<dynamic>> getArtifacts() async {
    final token = await getToken();
    final response = await http.get(
      Uri.parse('$baseUrl/artifacts'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw Exception('Failed to load artifacts');
  }

  static Future<Map<String, dynamic>> getArtifactRule(int artifactId) async {
    final token = await getToken();
    final response = await http.get(
      Uri.parse('$baseUrl/artifacts/$artifactId/rule'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw Exception('Failed to load rule');
  }

  static Future<Map<String, dynamic>> getDashboardStats() async {
    final token = await getToken();
    final response = await http.get(
      Uri.parse('$baseUrl/dashboard/stats'),
      headers: {'Authorization': 'Bearer $token'},
    );
    if (response.statusCode == 200) return jsonDecode(response.body);
    throw Exception('Failed to load stats');
  }
}
