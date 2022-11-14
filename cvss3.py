#CVSS3
#AV=Attack Vector, AC=Attack Complexity, PR=Privileges Required, 
#UI=User Interactions, S=Scope, C=Confidentiality Impact, I=Integrity 
#Impact, A= Availability Impact, E=Exploit Code Maturity, RL=Remediation Level,
#RC=Report Confidence 

import math

def round_up(number):                                                            
    number_up = math.ceil(10*number)/10
    return number_up

def raiting(number):                                #evaluation function

    if number == 0:
        rait = 'None'
    elif number < 4:
        rait = 'Low'
    elif (number > 3.9) and (number < 7):
        rait = 'Average'
    elif (number > 6.9) and (number < 9):
        rait = 'High'
    else:
        rait = 'Critical'

    return rait
def start():
    try:                                               
                                                                        
        AV = float(input('Enter AV --> '))
        AC = float(input('Enter AC --> '))
        PR = float(input('Enter  PR --> '))
        UI = float(input('Enter UI --> '))
        S = int(input('Enter S --> '))
        if S>1:
            input('Data entry error ')
            start()
        C = float(input('Enter C --> '))
        I = float(input('Enter I --> '))
        A = float(input('Enter A --> '))

    except ValueError:
        input('Data entry error \n Press Enter re-enter data')
        start()


    Exploitability = 8.22 * AV * AC * PR * UI
    ImpactBase = 1 - ((1 - C) * (1 - I) * (1 - A))
    if S == 0:
        Impact = 6.42 * ImpactBase
        BaseScore = round_up(round_up(min(Impact + Exploitability, 10)))
    elif S == 1:
        Impact = 7.52 * (ImpactBase - 0.029) - 3.25 * (ImpactBase - 0.02) ** 15
        BaseScore = round_up(min(1.08 * (Impact + Exploitability), 10)) 
    print('Base Score')
    print('Qualitative assessment: ', raiting(BaseScore))
    print('Quantification: ', BaseScore)

    print('Data entry for time estimation')
    try:                                                
        E = float(input('Enter E --> '))
        RL = float(input('Enter RL --> '))
        RC = float(input('Enter RC --> '))
    except ValueError:
        input('Data entry error \n press Enter to re-enter data')
        start()

    TempScore = round_up(BaseScore * E * RL * RC)        
    print('Time estimate')
    print('Qualitative assessment: ', raiting(TempScore))
    print('Quantification: ', TempScore)
    input('Press Enter to close the console')
if __name__=='__main__':
    start()