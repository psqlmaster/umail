CC = gcc
CFLAGS = -Os -Wall
LDFLAGS = -lssl -lcrypto

TARGET = umail
INSTALL_DIR = /usr/bin

all: $(TARGET)

$(TARGET): umail.c
	@echo "Building $(TARGET)..."
	$(CC) $(CFLAGS) -o $(TARGET) umail.c $(LDFLAGS)
	@echo "Stripping symbols to reduce size..."
	strip $(TARGET)
	@echo "Build complete."

install: $(TARGET)
	@echo "Installing $(TARGET) to $(INSTALL_DIR)..."
	install -m 755 $(TARGET) $(INSTALL_DIR)/$(TARGET)
	@echo "Installation successful. You can now run 'umail'."

clean:
	@echo "Cleaning up..."
	rm -f $(TARGET)

uninstall:
	@echo "Removing $(TARGET) from $(INSTALL_DIR)..."
	rm -f $(INSTALL_DIR)/$(TARGET)
	@echo "Uninstallation complete."

.PHONY: all install clean uninstall
