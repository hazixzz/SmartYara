// Saves bytes as a file download. The browser version uses package:web;
// other platforms (e.g. `flutter run -d windows`) get the stub.
export 'file_download_stub.dart'
    if (dart.library.js_interop) 'file_download_web.dart';
