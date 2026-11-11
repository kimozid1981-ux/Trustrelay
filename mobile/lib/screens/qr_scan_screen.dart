import 'package:material_ui/material_ui.dart';
import 'package:mobile_scanner/mobile_scanner.dart';

/// Reads a QR code with the camera and returns its raw text. Nothing is opened or followed: the content
/// is only handed back to the check screen for analysis.
class QrScanScreen extends StatefulWidget {
  const QrScanScreen({super.key});
  @override
  State<QrScanScreen> createState() => _QrScanScreenState();
}

class _QrScanScreenState extends State<QrScanScreen> {
  bool _done = false;
  @override
  Widget build(BuildContext context) {
    return Scaffold(
      appBar: AppBar(title: const Text('QR')),
      body: MobileScanner(
        onDetect: (capture) {
          final value = capture.barcodes.map((b) => b.rawValue).whereType<String>().firstOrNull;
          if (value != null && !_done) {
            _done = true;
            Navigator.of(context).pop(value);
          }
        },
      ),
    );
  }
}
