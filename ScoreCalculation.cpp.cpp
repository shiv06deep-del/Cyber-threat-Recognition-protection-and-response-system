#include<iostream>
#include<string>
using namespace std;
class Threat{
    private:
        string threatName;
        string classification;
        int likelihood;
        int severity;
        int impact;
        int frequency;
        double riskScore;
    public:
       Threat(const char* threatName, int frequency){
        this->threatName = threatName;
        this->frequency = frequency;
       }
       // Setting factors for different types of threats 
       void AnalysingFactors(){
            if (strcmp(name, "SQL Injection") == 0)
            {
                severity = 9;
                likelihood = 8;
                impact = 9;
            }

        else if (strcmp(name, "Phishing") == 0)
            {
                severity = 7;
                likelihood = 8;
                impact = 6;
            }

        else if (strcmp(name, "Port Scan") == 0)
            {
                severity = 4;
                likelihood = 5;
                impact = 3;
            }

        else if (strcmp(name, "DDoS") == 0)
            {
                severity = 9;
                likelihood = 7;
                impact = 9;
            }

        else if (strcmp(name, "Malware") == 0)
            {
                severity = 9;
                likelihood = 7;
                impact = 10;
            }

        else if (strcmp(name, "Brute Force") == 0)
            {
                severity = 7;
                likelihood = 7;
                impact = 7;
            }

        else
            {
                severity = 5;
                likelihood = 5;
                impact = 5;
            }

       }
       // calclulating risk score
       void calculateScore(){
        riskScore = ( likelihood + frequency + impact + severity ) / 4.0;
       }

       void displayThreatAnalysis(){
        cout << "Threat Name : " << threatName << endl;
        cout << "Likelihood : " << likelihood << endl;
        cout << "Severity : " << severity << endl;
        cout << "Impact : " << impact << endl;
        cout << "Risk Score Determined : " << riskScore << endl;
       }
// Classification of threat on basis of score
       void classifyThreat(){
            if (riskScore >= 7)
                {
                    strcpy(classification, "HIGH");
                }

            else if (riskScore >= 4)
                {
                    strcpy(classification, "MEDIUM");
                }

            else
                {
                    strcpy(classification, "LOW");
                }
       }

}