from pathlib import Path
import os
import random

# state - capital dictionary
capitals = {
    "Alabama": "Montgomery",
    "Alaska": "Juneau",
    "Arizona": "Phoenix",
    "Arkansas": "Little Rock",
    "California": "Sacramento",
    "Colorado": "Denver",
    "Connecticut": "Hartford",
    "Delaware": "Dover",
    "Florida": "Tallahassee",
    "Georgia": "Atlanta",
    "Hawaii": "Honolulu",
    "Idaho": "Boise",
    "Illinois": "Springfield",
    "Indiana": "Indianapolis",
    "Iowa": "Des Moines",
    "Kansas": "Topeka",
    "Kentucky": "Frankfort",
    "Louisiana": "Baton Rouge",
    "Maine": "Augusta",
    "Maryland": "Annapolis",
    "Massachusetts": "Boston",
    "Michigan": "Lansing",
    "Minnesota": "Saint Paul",
    "Mississippi": "Jackson",
    "Missouri": "Jefferson City",
    "Montana": "Helena",
    "Nebraska": "Lincoln",
    "Nevada": "Carson City",
    "New Hampshire": "Concord",
    "New Jersey": "Trenton",
    "New Mexico": "Santa Fe",
    "New York": "Albany",
    "North Carolina": "Raleigh",
    "North Dakota": "Bismarck",
    "Ohio": "Columbus",
    "Oklahoma": "Oklahoma City",
    "Oregon": "Salem",
    "Pennsylvania": "Harrisburg",
    "Rhode Island": "Providence",
    "South Carolina": "Columbia",
    "South Dakota": "Pierre",
    "Tennessee": "Nashville",
    "Texas": "Austin",
    "Utah": "Salt Lake City",
    "Vermont": "Montpelier",
    "Virginia": "Richmond",
    "Washington": "Olympia",
    "West Virginia": "Charleston",
    "Wisconsin": "Madison",
    "Wyoming": "Cheyenne",
}
# generate quiz files:
for num in range(35):
    with (
        open(
            Path.cwd() / "project_4" / f"quiz_file_{num+1}.txt", "w", encoding="utf-8"
        ) as quiz_file,
        open(
            Path.cwd() / "project_4" / f"quiz_file_{num+1}_answer.txt",
            "w",
            encoding="utf-8",
        ) as answer_file,
    ):
        quiz_file.write("Class: \n")
        quiz_file.write("Name: \n")
        quiz_file.write(" " * 20 + f"State capitals form {num + 1}\n\n")

        states = list(capitals)
        random.shuffle(states)

        for quest_num in range(50):
            correct_answer = capitals[states[quest_num]]
            answer_pool = list(capitals.values())
            answer_pool.remove(correct_answer)
            answers = random.sample(answer_pool, 3)
            answers.append(correct_answer)
            random.shuffle(answers)

            quiz_file.write(
                f"{quest_num+1}. What is the capital of {states[quest_num]}? \n"
            )
            for i in range(4):

                quiz_file.write(f"{'ABCD'[i]}. {answers[i]}\n")
            quiz_file.write("\n")
            answer_file.write(
                f"{quest_num+1}. {'ABCD'[answers.index(correct_answer)]}\n"
            )
