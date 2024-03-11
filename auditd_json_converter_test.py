import unittest
import auditd_json_converter as ajc
from unittest.mock import patch
import tempfile
import os
import json

class TestHexToAscii(unittest.TestCase):

    ############################
    # Hex Test Cases
    ############################
    def test_hex_to_ascii(self):
        self.assertEqual(ajc.hex_to_ascii("48656c6c6f2c20776f726c6421"), "Hello, world!")
        self.assertEqual(ajc.hex_to_ascii("5465737420537472696e67"), "Test String")
        self.assertEqual(ajc.hex_to_ascii(""), "")

    def test_process_hex_line(self):
        input = "32303037343635373337340A747970653D53595343414C4C206D73673D617564697428313731303131313531302E3936333A313134293A20617263683D63303030303033652073797363616C6C3D353920737563636573733D79657320657869743D302061303D3535373262356534396231302061313D353537326234"
        expectation = "type=SYSCALL msg=audit(1710111510.963:114): arch=c000003e syscall=59 success=yes exit=0 a0=5572b5e49b10 a1=5572b4"
        
        if ajc.is_hex(input):
            ajc.hex_to_ascii(input) is expectation
        else:
            print("Input is not a HEX String")

    def test_is_hex(self):
        self.assertTrue(ajc.is_hex("48656c6c6f2c20776f726c6421"))
        self.assertTrue(ajc.is_hex("2303037343635373337340A74797065"))
        self.assertFalse(ajc.is_hex("123CAFFEBABEnotAHEXString"))

    ############################
    # Make Readable Test Cases
    ############################
    def test_known_keys(self):
        self.assertEqual(ajc.make_readable('acct'), 'account')
        self.assertEqual(ajc.make_readable('res'), 'result')
        self.assertEqual(ajc.make_readable('comm'), 'command-line')
        self.assertEqual(ajc.make_readable('pid'), 'process_id')
        self.assertEqual(ajc.make_readable('uid'), 'user_id')
        self.assertEqual(ajc.make_readable('auid'), 'audit_user_id')
        self.assertEqual(ajc.make_readable('exe'), 'executable')

    def test_unknown_key(self):
        self.assertEqual(ajc.make_readable('unknown'), 'unknown')   
    
    ############################
    # Verbose Test Cases
    ############################
    @patch('builtins.print')
    def test_prints_when_verbose(self, mock_print):
        ajc.VERBOSE = True
        ajc.verbose_print('Test message')
        mock_print.assert_called_once_with('Test message')


    @patch('builtins.print')
    def test_does_not_print_when_not_verbose(self, mock_print):
        global VERBOSE
        VERBOSE = False
        ajc.verbose_print('Test message')
        mock_print.assert_not_called()

    ############################
    # Get Time Test Cases
    ############################
    def test_get_time(self):
        self.assertEqual(ajc.get_time('msg=audit(1532489108.216:3721):'), '2018-07-25 03:25:08')
        self.assertEqual(ajc.get_time('msg=audit(1532489109.283:3722):'), '2018-07-25 03:25:09')

    def test_get_wrong_time(self):
        self.assertFalse(ajc.get_time('msg=audit(1532489108.216:3721):') == '2019-07-25 03:25:08')
        self.assertFalse(ajc.get_time('msg=audit(1532489109.283:3722):') == '2019-07-25 03:25:09')

    ############################
    # Process Line Test Cases
    ############################
    def test_process_line(self):
        input_line = 'type=EXECVE msg=audit(1532489108.216:3721): argc=2 a0="cat" a1="10-procmon.rules"'
        expectation = {'type': 'EXECVE', 'timestamp': '2018-07-25 03:25:08', 'argc': '2', 'a0': 'cat', 'a1': '10-procmon.rules'}
        self.assertEqual(ajc.process_line(input_line), expectation)

class TestProcessFile(unittest.TestCase):
    def setUp(self):
        self.input_file = tempfile.NamedTemporaryFile(delete=False)
        self.input_file.write(b'OPERATOR_LOG1\nOPERATOR_LOG2\n')
        self.input_file.close()

        self.output_file = tempfile.NamedTemporaryFile(delete=False)
        self.output_file.close()

    def tearDown(self):
        os.unlink(self.input_file.name)
        os.unlink(self.output_file.name)

    def test_process_file(self):
        ajc.process_file(self.input_file.name, self.output_file.name, ['OPERATOR_LOG1', 'OPERATOR_LOG2'])

        with open(self.output_file.name, 'r') as f:
            entries = json.load(f)

        self.assertEqual(len(entries), 2)

if __name__ == '__main__':
    unittest.main()