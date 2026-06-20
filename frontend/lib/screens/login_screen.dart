import 'package:flutter/material.dart';
import '../services/api_service.dart';
import 'dashboard_screen.dart';

class LoginScreen extends StatefulWidget {
  const LoginScreen({super.key});
  @override
  State<LoginScreen> createState() => _LoginScreenState();
}

class _LoginScreenState extends State<LoginScreen> {
  final _userCtrl = TextEditingController();
  final _passCtrl = TextEditingController();
  bool _loading = false;
  bool _isRegister = false;
  String? _error;

  Future<void> _submit() async {
    setState(() { _loading = true; _error = null; });
    try {
      if (_isRegister) {
        await ApiService.register(_userCtrl.text.trim(), _passCtrl.text);
        setState(() { _isRegister = false; _error = null; });
        _showSnack('Account created! Please log in.');
      } else {
        await ApiService.login(_userCtrl.text.trim(), _passCtrl.text);
        if (mounted) {
          Navigator.pushReplacement(context,
              MaterialPageRoute(builder: (_) => const DashboardScreen()));
        }
      }
    } catch (e) {
      setState(() { _error = e.toString().replaceFirst('Exception: ', ''); });
    } finally {
      setState(() { _loading = false; });
    }
  }

  Color get _accentColor => _isRegister
      ? const Color(0xFF7BFF8C)
      : const Color(0xFF00D4FF);

  Color get _panelColor => _isRegister
      ? const Color(0xFF081E14)
      : const Color(0xFF112240);

  String get _heading => _isRegister ? 'Create your account' : 'Welcome back';
  String get _subheading => _isRegister
      ? 'Join SmartYARA to generate secure YARA rules.'
      : 'Sign in to continue to your analyst dashboard.';

  IconData get _topIcon => _isRegister ? Icons.person_add_alt_1 : Icons.lock_open;

  void _showSnack(String msg) {
    ScaffoldMessenger.of(context)
        .showSnackBar(SnackBar(content: Text(msg)));
  }

  @override
  Widget build(BuildContext context) {
    return Scaffold(
      body: Center(
        child: SingleChildScrollView(
          child: Container(
            width: 420,
            padding: const EdgeInsets.all(36),
            decoration: BoxDecoration(
              color: _panelColor,
              borderRadius: BorderRadius.circular(20),
              border: Border.all(color: _accentColor.withOpacity(0.3)),
              boxShadow: [
                BoxShadow(
                  color: _accentColor.withOpacity(0.12),
                  blurRadius: 42,
                  spreadRadius: 6,
                )
              ],
            ),
            child: Column(
              mainAxisSize: MainAxisSize.min,
              children: [
                Row(
                  children: [
                    Expanded(child: _buildModeTab(false, 'Sign In')),
                    const SizedBox(width: 12),
                    Expanded(child: _buildModeTab(true, 'Sign Up')),
                  ],
                ),
                const SizedBox(height: 28),
                Container(
                  width: 72,
                  height: 72,
                  decoration: BoxDecoration(
                    color: _accentColor.withOpacity(0.15),
                    borderRadius: BorderRadius.circular(18),
                  ),
                  child: Icon(_topIcon, color: _accentColor, size: 36),
                ),
                const SizedBox(height: 18),
                Text('SmartYARA',
                    style: TextStyle(
                      fontSize: 30,
                      fontWeight: FontWeight.bold,
                      color: _accentColor,
                    )),
                const SizedBox(height: 6),
                Text(_subheading,
                    textAlign: TextAlign.center,
                    style: const TextStyle(fontSize: 13, color: Colors.white54)),
                const SizedBox(height: 28),

                Align(
                  alignment: Alignment.centerLeft,
                  child: Text(_heading,
                      style: const TextStyle(
                          fontSize: 22,
                          fontWeight: FontWeight.w700,
                          color: Colors.white)),
                ),
                const SizedBox(height: 16),
                _buildField(_userCtrl, 'Username', Icons.person_outline),
                const SizedBox(height: 16),
                _buildField(_passCtrl, 'Password', Icons.lock_outline,
                    obscure: true),
                const SizedBox(height: 12),

                if (_error != null)
                  Container(
                    padding: const EdgeInsets.all(12),
                    decoration: BoxDecoration(
                      color: Colors.red.withOpacity(0.12),
                      borderRadius: BorderRadius.circular(10),
                      border: Border.all(color: Colors.red.withOpacity(0.45)),
                    ),
                    child: Row(children: [
                      const Icon(Icons.error_outline, color: Colors.red, size: 18),
                      const SizedBox(width: 10),
                      Expanded(child: Text(_error!,
                          style: const TextStyle(color: Colors.red, fontSize: 13))),
                    ]),
                  ),

                const SizedBox(height: 24),
                SizedBox(
                  width: double.infinity,
                  height: 50,
                  child: ElevatedButton(
                    onPressed: _loading ? null : _submit,
                    style: ElevatedButton.styleFrom(
                      backgroundColor: _accentColor,
                      foregroundColor: const Color(0xFF0D1B2A),
                      shape: RoundedRectangleBorder(
                          borderRadius: BorderRadius.circular(14)),
                    ),
                    child: _loading
                        ? const SizedBox(
                            width: 20,
                            height: 20,
                            child: CircularProgressIndicator(
                                strokeWidth: 2, color: Color(0xFF0D1B2A)))
                        : Text(
                            _isRegister ? 'Create Account' : 'Sign In',
                            style: const TextStyle(
                                fontWeight: FontWeight.bold, fontSize: 16),
                          ),
                  ),
                ),
                const SizedBox(height: 18),
                TextButton(
                  onPressed: () => setState(() {
                    _isRegister = !_isRegister; _error = null;
                  }),
                  child: Text(
                    _isRegister
                        ? 'Already have an account? Sign in'
                        : 'New here? Create an account',
                    style: TextStyle(color: _accentColor, fontSize: 14),
                  ),
                ),
                const SizedBox(height: 12),
                const Text('Default: admin / admin123',
                    style: TextStyle(color: Colors.white24, fontSize: 11)),
              ],
            ),
          ),
        ),
      ),
    );
  }

  Widget _buildModeTab(bool value, String label) {
    final active = _isRegister == value;
    return GestureDetector(
      onTap: () => setState(() {
        _isRegister = value;
        _error = null;
      }),
      child: Container(
        height: 50,
        decoration: BoxDecoration(
          color: active ? _accentColor.withOpacity(0.18) : Colors.white12,
          borderRadius: BorderRadius.circular(14),
          border: Border.all(
            color: active ? _accentColor : Colors.white10,
            width: active ? 1.5 : 1,
          ),
        ),
        child: Center(
          child: Text(label,
              style: TextStyle(
                color: active ? _accentColor : Colors.white70,
                fontWeight: active ? FontWeight.w700 : FontWeight.w500,
              )),
        ),
      ),
    );
  }

  Widget _buildField(TextEditingController ctrl, String label,
      IconData icon, {bool obscure = false}) {
    return TextField(
      controller: ctrl,
      obscureText: obscure,
      onSubmitted: (_) => _submit(),
      style: const TextStyle(color: Colors.white),
      decoration: InputDecoration(
        labelText: label,
        labelStyle: const TextStyle(color: Colors.white54),
        prefixIcon: Icon(icon, color: _accentColor, size: 20),
        filled: true,
        fillColor: const Color(0xFF0D1B2A),
        border: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: Colors.white24),
        ),
        enabledBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: Colors.white24),
        ),
        focusedBorder: OutlineInputBorder(
          borderRadius: BorderRadius.circular(12),
          borderSide: BorderSide(color: _accentColor),
        ),
      ),
    );
  }
}
