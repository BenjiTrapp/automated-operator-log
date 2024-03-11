PYTHON_FILE = auditd_json_converter.py
EXECUTABLE = dist/auditd_json_converter

.PHONY: build test clean

test: 
    python -m unittest auditd_json_converter_test.py

test_convert:
    python auditd_json_converter.py -f ./test_data/audit.log -o /tmp/bla.json -v &&  cat /tmp/bla.json 

build: $(EXECUTABLE)

$(EXECUTABLE): $(PYTHON_FILE)
    pyinstaller --onefile $(PYTHON_FILE)

clean:
    rm -rf build dist __pycache__
    rm -f *.spec