import 'package:image_picker/image_picker.dart';
import 'package:material_ui/material_ui.dart';

import '../api/client.dart';
import '../app_state.dart';
import 'analysis_screen.dart';
import 'qr_scan_screen.dart';

const kKinds = ['url', 'message', 'image', 'qr', 'advert', 'payment'];

class CheckScreen extends StatefulWidget {
  const CheckScreen({super.key});
  @override
  State<CheckScreen> createState() => _CheckScreenState();
}

class _CheckScreenState extends State<CheckScreen> {
  String _kind = 'url';
  final _text = TextEditingController();
  XFile? _image;
  bool _busy = false;
  String? _error;

  Future<void> _pick() async {
    // Gallery only: screenshots are what users typically want to check, and no camera permission is needed.
    final f = await ImagePicker().pickImage(source: ImageSource.gallery, maxWidth: 2400, maxHeight: 2400);
    if (f != null) setState(() => _image = f);
  }

  Future<void> _scan() async {
    final value = await Navigator.of(context).push<String>(MaterialPageRoute(builder: (_) => const QrScanScreen()));
    if (value != null) setState(() => _text.text = value);
  }

  Future<void> _submit(AppState app) async {
    setState(() {
      _busy = true;
      _error = null;
    });
    try {
      final body = <String, dynamic>{'kind': _kind};
      if (_image != null && (_kind == 'image' || _kind == 'qr')) {
        final up = await app.api.upload(_image!.name, await _image!.readAsBytes()) as Map<String, dynamic>;
        body['upload_id'] = up['id'];
      } else {
        body['text'] = _text.text.trim();
      }
      final r = await app.api.call('POST', '/analyses', body: body) as Map<String, dynamic>;
      if (!mounted) return;
      _text.clear();
      setState(() => _image = null);
      await Navigator.of(context).push(MaterialPageRoute(builder: (_) => AnalysisScreen(id: r['id'] as String)));
    } on ApiException catch (e) {
      setState(() => _error = e.detail);
    } catch (_) {
      setState(() => _error = app.s.t('error'));
    } finally {
      if (mounted) setState(() => _busy = false);
    }
  }

  @override
  Widget build(BuildContext context) {
    final app = AppScope.of(context);
    final s = app.s;
    final usesImage = _kind == 'image' || _kind == 'qr';
    final canSubmit = !_busy && ((_kind == 'image' && _image != null) || (_kind != 'image' && (_text.text.trim().isNotEmpty || _image != null)));
    return ListView(padding: const EdgeInsets.all(16), children: [
      Text(s.t('checkTitle'), style: Theme.of(context).textTheme.headlineSmall),
      const SizedBox(height: 12),
      Wrap(spacing: 8, runSpacing: 8, children: [
        for (final k in kKinds)
          ChoiceChip(
              label: Text(s.t('kind_$k')),
              selected: _kind == k,
              onSelected: (_) => setState(() {
                    _kind = k;
                    _image = null;
                    _error = null;
                  })),
      ]),
      const SizedBox(height: 12),
      if (_kind != 'image')
        TextField(
          key: const Key('input'),
          controller: _text,
          onChanged: (_) => setState(() {}),
          minLines: _kind == 'url' || _kind == 'qr' ? 1 : 4,
          maxLines: _kind == 'url' || _kind == 'qr' ? 2 : 10,
          maxLength: 20000,
          keyboardType: _kind == 'url' ? TextInputType.url : TextInputType.multiline,
          decoration: InputDecoration(labelText: s.t('kind_$_kind'), hintText: s.t('inputHint'), border: const OutlineInputBorder()),
        ),
      if (usesImage)
        Row(children: [
          OutlinedButton.icon(onPressed: _pick, icon: const Icon(Icons.image), label: Text(s.t('pickImage'))),
          const SizedBox(width: 8),
          if (_kind == 'qr') OutlinedButton.icon(onPressed: _scan, icon: const Icon(Icons.qr_code_scanner), label: Text(s.t('scanQr'))),
        ]),
      if (_image != null) Padding(padding: const EdgeInsets.only(top: 8), child: Text(_image!.name)),
      const SizedBox(height: 8),
      Text(s.t('neverShare'), style: Theme.of(context).textTheme.bodySmall),
      if (_error != null) Text(_error!, style: TextStyle(color: Theme.of(context).colorScheme.error)),
      const SizedBox(height: 12),
      FilledButton(onPressed: canSubmit ? () => _submit(app) : null, child: Text(_busy ? s.t('analysing') : s.t('analyse'))),
    ]);
  }
}
