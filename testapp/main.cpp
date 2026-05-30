#include <iostream>
#include <string>
#include <vector>

static const char* bannerLine = "=== ComProtector Test Application ===";

int addNumbers(int firstValue, int secondValue) {
    return firstValue + secondValue;
}

int main() {
    std::cout << bannerLine << std::endl;
    std::cout << "Initializing protected sample program" << std::endl;

    std::vector<std::string> messages = {
        "Loading configuration data",
        "Connecting to secret service endpoint",
        "Authentication token verified",
        "Processing encrypted payload"
    };

    for (const std::string& message : messages) {
        std::cout << "[status] " << message << std::endl;
    }

    int computedSum = addNumbers(40, 2);
    std::cout << "Computed answer is " << computedSum << std::endl;
    std::cout << "All operations completed successfully" << std::endl;
    return 0;
}
