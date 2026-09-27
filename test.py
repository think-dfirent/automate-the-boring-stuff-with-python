import openpyxl

wb = openpyxl.Workbook()
sheet = wb.active

# 1. Generate data for TWO columns
for i in range(1, 11):
    sheet["A" + str(i)] = i * 2  # Column A (Apples)
    sheet["B" + str(i)] = i * 3  # Column B (Oranges)

# 2. Create a Reference for each column (Where is the data?)
# min_col=1 is Column A, min_col=2 is Column B
ref_apples = openpyxl.chart.Reference(
    sheet, min_col=1, min_row=1, max_col=1, max_row=10
)
ref_oranges = openpyxl.chart.Reference(
    sheet, min_col=2, min_row=1, max_col=2, max_row=10
)

# 3. Create a Series for each Reference (What does the legend say?)
series_apples = openpyxl.chart.Series(ref_apples, title="Apples")
series_oranges = openpyxl.chart.Series(ref_oranges, title="Oranges")

# 4. Create the chart and append BOTH series
chart_obj = openpyxl.chart.BarChart()
chart_obj.title = "Apples vs Oranges"

chart_obj.append(series_apples)  # Draws the first set of bars
chart_obj.append(series_oranges)  # Draws the second set of bars right next to them

# 5. Place the chart and save
sheet.add_chart(chart_obj, "D5")
wb.save("TwoColumnChart.xlsx")
