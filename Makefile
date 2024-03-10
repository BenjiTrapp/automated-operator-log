PYTHON_FILE = auditd_json_converter.py
EXECUTABLE = dist/auditd_json_converter

.PHONY: build clean

build: $(EXECUTABLE)

$(EXECUTABLE): $(PYTHON_FILE)
    pyinstaller --onefile $(PYTHON_FILE)

clean:
    rm -rf build dist __pycache__
    rm -f *.spec