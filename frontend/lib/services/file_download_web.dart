import 'dart:js_interop';
import 'dart:typed_data';
import 'package:web/web.dart' as web;

// Wraps the bytes in a Blob and clicks a temporary <a download> link.
Future<void> saveFile(String filename, Uint8List bytes) async {
  final blob = web.Blob(
    [bytes.toJS].toJS,
    web.BlobPropertyBag(type: 'text/plain'),
  );
  final url = web.URL.createObjectURL(blob);
  final anchor = web.HTMLAnchorElement()
    ..href = url
    ..download = filename
    ..style.display = 'none';
  web.document.body!.append(anchor);
  anchor.click();
  anchor.remove();
  web.URL.revokeObjectURL(url);
}
