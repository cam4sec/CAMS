package de.upb.ra.xlsxUtils;

import de.upb.ra.securityCriticalityAssessmentModel.LowLevelMeasure;
import lombok.extern.slf4j.Slf4j;
import lombok.val;
import org.apache.poi.ss.usermodel.*;
import org.apache.poi.xssf.usermodel.XSSFSheet;
import org.apache.poi.xssf.usermodel.XSSFWorkbook;

import java.io.FileOutputStream;
import java.io.IOException;
import java.util.*;
import java.util.stream.Stream;

/**
 * Utility class for writing to XLSX file
 *
 * @author Ranjith K
 * @date 19.07.24
 */
@Slf4j
public class ExcelWriter {
    private final String[] COLUMN_HEADERS;
    private final Map<String, Integer> categoryIndex;

    private final XSSFWorkbook workbook;
    private final XSSFSheet sheet;
    private final String xlsxFilePath;

    public ExcelWriter(String xlsxFilePath, List<String> categoriesName) {
        this.xlsxFilePath = xlsxFilePath;

        String[] initialHeader = {
                "Method Name", "SCIS", "SummedLowLevelMeasures"
        };

        List<String> freqHeader = new ArrayList<>();

        for (val categoryName : categoriesName) {
            freqHeader.add(categoryName + "-SrcFreq");
            freqHeader.add(categoryName + "-SnkFreq");
            freqHeader.add(categoryName + "-SanFreq");
            freqHeader.add(categoryName + "-ProFreq");
        }

        this.COLUMN_HEADERS = Stream.concat(Arrays.stream(initialHeader), Arrays.stream(freqHeader.toArray(new String[0])))
                .toArray(String[]::new);

        var index = 7;
        categoryIndex = new HashMap<>();

        for (val categoryName : categoriesName) {
            categoryIndex.put(categoryName, index);
            index += 4;
        }

        // Create a new workbook and sheet
        workbook = new XSSFWorkbook();
        sheet = workbook.createSheet("Security Critical Metrics");

        // Create the header row
        createHeaderRow();

        // Add sample data
        //addDataToSheet(sheet, "method1", "file1.json", 10, true, true, false);
    }

    public void save() {
        // Write the workbook to a file
        try (FileOutputStream fileOut = new FileOutputStream(xlsxFilePath)) {
            workbook.write(fileOut);
        } catch (IOException e) {
            log.error(e.getMessage(), e);
        } finally {
            try {
                workbook.close();
            } catch (IOException e) {
                log.error(e.getMessage(), e);
            }
        }
    }

    private void createHeaderRow() {
        Row headerRow = sheet.createRow(1);
        for (int i = 1; i <= COLUMN_HEADERS.length; i++) {
            Cell cell = headerRow.createCell(i);
            cell.setCellValue(COLUMN_HEADERS[i - 1]);
            CellStyle style = sheet.getWorkbook().createCellStyle();
            Font font = sheet.getWorkbook().createFont();
            font.setBold(true);
            style.setFont(font);
            cell.setCellStyle(style);
        }
    }

    public void addDataToSheet(String mName, double scis, double summedLowLevelMeasures, Map<String, LowLevelMeasure> categoryToFreqMap) {
        int rowCount = sheet.getLastRowNum();
        Row row = sheet.createRow(++rowCount);

        row.createCell(1).setCellValue(mName);
        row.createCell(2).setCellValue(scis);
        row.createCell(6).setCellValue(summedLowLevelMeasures);

        for (val entry : categoryIndex.entrySet()) {
            val lowLevelMeasure = categoryToFreqMap.getOrDefault(
                            entry.getKey(),
                            new LowLevelMeasure(new ArrayList<>())
                    );
            row.createCell(entry.getValue()).setCellValue(lowLevelMeasure.getSourceFreq());
            row.createCell(entry.getValue() + 1).setCellValue(lowLevelMeasure.getSinkFreq());
            row.createCell(entry.getValue() + 2).setCellValue(lowLevelMeasure.getSanitizerFreq());
            row.createCell(entry.getValue() + 3).setCellValue(lowLevelMeasure.getPropagatorFreq());
        }
    }
}