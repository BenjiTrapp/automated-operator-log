PYTHON_FILE = auditd_json_converter.py
EXECUTABLE = dist/auditd_json_converter

.PHONY: test clean

test: 
		python3 -m unittest auditd_json_converter_test.py

test_convert:
		python3 auditd_json_converter.py -f ./test_data/audit.log -o /tmp/bla.json -v &&  cat /tmp/bla.json

test_hex_convert:
		python3 auditd_json_converter.py -f ./test_data/audit_hex.log -o /tmp/bla_hex.json &&  cat /tmp/bla_hex.json

#build: $(EXECUTABLE)
#
#$(EXECUTABLE): $(PYTHON_FILE)
#    pyinstaller --onefile $(PYTHON_FILE)

clean:
		rm -rf build dist __pycache__
		rm -f *.spec
