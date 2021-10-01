#include "iostream"
#include "parser.cpp"

// todo: make default.policy the default one unless given other arguments
// todo: possibly change stream-name to data-stream
int main(int argc, char** argv){
    std::string configFilePath("default.policy"), availableStreamsFilePath ("policies/available_streams");

    // only allowing -f configFilePath to change policy file name
    // very crude way of doing this, but it works for now
    if (argc == 3) {
        std::string s = "-f";
        if ((s.compare(argv[1])) == 0) {
            configFilePath = argv[2];
        } else {
            return -1;
        }
    }

    // this createsa a parser with the path to the config file and the available_streams file
    // the resulting ABE policy is automatically generated
    mguard::PolicyParser pp(configFilePath, availableStreamsFilePath);

//    // this is just for testing purposes
//    std::cout << pp << std::endl;

    // this is how you grab the ABE policy
    const std::string& ABEPolicy = pp.getABEPolicy();

    std::cout   <<  ABEPolicy   <<  std::endl;

    return 0;

}