import json
import unittest

import native_provider_wire as W


class WireTests(unittest.TestCase):
    def native(self):
        return {'model': 'deepseek-flash', 'tools': [
            {'type': 'namespace', 'name': 'functions', 'tools': [
                {'type': 'custom', 'name': 'exec', 'description': 'Execute actual V8 JavaScript',
                 'format': {'type': 'grammar', 'syntax': 'lark', 'definition': 'start: /.+/'}},
                {'type': 'function', 'name': 'exec_command', 'parameters': {'type': 'object'}}]}],
            'input': []}

    def test_custom_and_namespace_are_reversible_not_a_tool_replacement(self):
        original = self.native()
        original['input'] = [
            {'type': 'custom_tool_call', 'name': 'exec', 'namespace': 'functions',
             'call_id': 'c1', 'input': 'text("你好")'},
            {'type': 'custom_tool_call_output', 'call_id': 'c1', 'output': '你好'}]
        outbound, receipt = W.prepare_request(original)
        self.assertEqual([tool['type'] for tool in outbound['tools']], ['function', 'function'])
        alias = outbound['input'][0]['name']
        self.assertEqual(receipt['tools'][alias]['name'], 'exec')
        self.assertEqual(json.loads(outbound['input'][0]['arguments']), {'input': 'text("你好")'})
        self.assertEqual(outbound['input'][1]['type'], 'function_call_output')
        self.assertEqual(original['input'][0]['type'], 'custom_tool_call')

    def test_stream_restores_custom_input_namespace_ids_and_usage(self):
        _, receipt = W.prepare_request(self.native())
        alias = next(key for key, value in receipt['tools'].items() if value['name'] == 'exec')
        code = 'text(await tools.exec_command({cmd:"pwd"}));'
        arguments = json.dumps({'input': code})
        item = {'id': 'i1', 'type': 'function_call', 'name': alias, 'call_id': 'c1', 'arguments': arguments}
        rows = [
            {'type': 'response.output_item.added', 'output_index': 0, 'item': {**item, 'arguments': ''}},
            {'type': 'response.function_call_arguments.delta', 'item_id': 'i1', 'delta': arguments},
            {'type': 'response.function_call_arguments.done', 'item_id': 'i1', 'arguments': arguments},
            {'type': 'response.output_item.done', 'output_index': 0, 'item': item},
            {'type': 'response.completed', 'response': {'id': 'r1', 'output': [item],
                'usage': {'input_tokens': 100, 'output_tokens': 40, 'total_tokens': 140}}}]
        raw = b''.join(b'data: '+W.canonical(row)+b'\n\n' for row in rows)
        translated = W.restore_response(raw, receipt)
        restored = [json.loads(block.split(b'data: ', 1)[1]) for block in translated.split(b'\n\n') if block]
        result = restored[-1]['response']['output'][0]
        self.assertEqual(result['type'], 'custom_tool_call')
        self.assertEqual(result['name'], 'exec')
        self.assertEqual(result['namespace'], 'functions')
        self.assertEqual(result['call_id'], 'c1')
        self.assertEqual(result['input'], code)
        self.assertEqual(restored[-1]['response']['usage'], rows[-1]['response']['usage'])
        self.assertEqual([row['sequence_number'] for row in restored], list(range(len(restored))))
        self.assertIn('response.custom_tool_call_input.delta', translated.decode())
        self.assertNotIn('response.function_call_arguments.delta', translated.decode())

    def test_unknown_output_alias_cannot_execute(self):
        _, receipt = W.prepare_request(self.native())
        raw = b'data: '+W.canonical({'type': 'response.output_item.added',
            'item': {'type': 'function_call', 'id': 'i', 'name': 'undeclared'}})+b'\n\n'
        with self.assertRaisesRegex(ValueError, 'undeclared'):
            W.restore_response(raw, receipt)

    def test_custom_wrapper_cannot_add_hidden_parameters(self):
        _, receipt = W.prepare_request(self.native())
        alias = next(key for key, value in receipt['tools'].items() if value['type'] == 'custom')
        raw = b'data: '+W.canonical({'type': 'response.completed', 'response': {'output': [
            {'type': 'function_call', 'name': alias, 'arguments': '{"input":"pwd","extra":1}'}]}})+b'\n\n'
        with self.assertRaises(ValueError): W.restore_response(raw, receipt)


if __name__ == '__main__':
    unittest.main()
