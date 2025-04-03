package main

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/xuri/excelize/v2"
)

// Определяем типы для парсинга XML.
// Используем innerxml для поля Data, чтобы получить содержимое с вложенными тегами.
type Workbook struct {
	XMLName xml.Name `xml:"Workbook"`
	Sheets  []Sheet  `xml:"Worksheet>Table"`
}

type Sheet struct {
	Rows []Row `xml:"Row"`
}

type Row struct {
	Cells []Cell `xml:"Cell"`
}

type Cell struct {
	// Берем содержимое ячейки как innerxml, чтобы потом можно было удалить HTML-теги из ссылок.
	Data string `xml:",innerxml"`
}

func main() {
	startTime := time.Now()
	defer func() {
		elapsed := time.Since(startTime)
		fmt.Printf("Скрипт выполнен за %v\n", elapsed)
	}()

	// Получаем директорию с бинарником
	dir, err := filepath.Abs(filepath.Dir(os.Args[0]))
	if err != nil {
		fmt.Printf("Ошибка получения директории: %v\n", err)
		return
	}
	fmt.Printf("Рабочая директория: %s\n", dir)

	// Распаковываем все ZIP-архивы
	unpackedFiles, err := unzipArchives(dir)
	if err != nil {
		fmt.Printf("Ошибка распаковки: %v\n", err)
		return
	}

	// Ищем все XML файлы (включая распакованные)
	xmlFiles := findXMLFiles(dir)
	if len(xmlFiles) == 0 {
		fmt.Println("Не найдено XML файлов для обработки")
		printDirectoryContents(dir) // Диагностика
		return
	}

	// Обрабатываем данные
	header := []string{
		"Задача", "IP-адрес", "Host_primary", "Операционная система",
		"Сервис/ПО", "ID", "CVE", "CVSS v2", "CVSS v3",
		"Уровень опасности", "Уязвимость", "Как исправить", "Ссылки",
		"Неустановленное обновление", "Ссылки на обновления",
		"Дата выпуска обновления", "Дата публикации",
	}

	var allData [][]string
	for _, file := range xmlFiles {
		fmt.Printf("Обработка файла: %s\n", file)
		rows := parseExcelXML(file)
		if rows != nil {
			allData = append(allData, rows...)
		}
	}

	// Создаем итоговый отчет
	outputPath := filepath.Join(dir, "combined_report.xlsx")
	if err := createExcel(outputPath, header, allData); err != nil {
		fmt.Printf("Ошибка создания отчета: %v\n", err)
		return
	}

	// Удаляем распакованные архивы
	for _, archive := range unpackedFiles {
		if err := os.Remove(archive); err != nil {
			fmt.Printf("Не удалось удалить архив %s: %v\n", archive, err)
		} else {
			fmt.Printf("Архив удален: %s\n", archive)
		}
	}

	fmt.Printf("Готово! Отчет сохранен: %s\n", outputPath)
}

// Функция поиска XML файлов
func findXMLFiles(dir string) []string {
	var files []string

	err := filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}

		if !info.IsDir() && strings.HasSuffix(strings.ToLower(info.Name()), ".xml") {
			absPath, err := filepath.Abs(path)
			if err != nil {
				return err
			}
			files = append(files, absPath)
			fmt.Printf("Найден XML файл: %s\n", path)
		}
		return nil
	})

	if err != nil {
		fmt.Printf("Ошибка поиска файлов: %v\n", err)
	}

	return files
}

// Вывод содержимого директории
func printDirectoryContents(dir string) {
	fmt.Println("\nТекущее содержимое директории:")
	files, err := os.ReadDir(dir)
	if err != nil {
		fmt.Printf("Ошибка чтения директории: %v\n", err)
		return
	}
	for _, file := range files {
		fmt.Println(file.Name())
	}
}

// Распаковывает все ZIP-архивы в директории
func unzipArchives(dir string) ([]string, error) {
	var processedArchives []string

	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, file := range files {
		if file.IsDir() || !strings.HasSuffix(strings.ToLower(file.Name()), ".zip") {
			continue
		}

		archivePath := filepath.Join(dir, file.Name())
		fmt.Printf("Распаковываем: %s\n", file.Name())

		if err := extractZip(archivePath, dir); err != nil {
			return processedArchives, fmt.Errorf("ошибка распаковки %s: %v", file.Name(), err)
		}

		processedArchives = append(processedArchives, archivePath)
	}

	return processedArchives, nil
}

// Извлекает файлы из ZIP-архива
func extractZip(src, dest string) error {
	r, err := zip.OpenReader(src)
	if err != nil {
		return err
	}
	defer r.Close()

	for _, f := range r.File {
		// Защита от path traversal
		fpath := filepath.Join(dest, filepath.Clean(f.Name))
		if !strings.HasPrefix(fpath, filepath.Clean(dest)+string(os.PathSeparator)) {
			return fmt.Errorf("недопустимый путь: %s", fpath)
		}

		if f.FileInfo().IsDir() {
			if err := os.MkdirAll(fpath, os.ModePerm); err != nil {
				return err
			}
			continue
		}

		if err := os.MkdirAll(filepath.Dir(fpath), os.ModePerm); err != nil {
			return err
		}

		outFile, err := os.OpenFile(fpath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, f.Mode())
		if err != nil {
			return err
		}

		rc, err := f.Open()
		if err != nil {
			outFile.Close()
			return err
		}

		_, err = io.Copy(outFile, rc)
		outFile.Close()
		rc.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// Удаляет HTML-теги из строки (например, тег <html:U>, <html:Font> и пр.)
func removeHTMLTags(s string) string {
	// Простой regexp для удаления тегов (не идеальное решение для сложного HTML)
	re := regexp.MustCompile(`</?[^>]+>`)
	return re.ReplaceAllString(s, "")
}

// Парсит XML файл с таблицей Excel
func parseExcelXML(filePath string) [][]string {
	xmlFile, err := os.ReadFile(filePath)
	if err != nil {
		fmt.Printf("Ошибка чтения %s: %v\n", filePath, err)
		return nil
	}

	var workbook Workbook
	if err := xml.Unmarshal(xmlFile, &workbook); err != nil {
		fmt.Printf("Ошибка парсинга %s: %v\n", filePath, err)
		return nil
	}

	var result [][]string
	for _, sheet := range workbook.Sheets {
		for _, row := range sheet.Rows {
			var rowData []string
			emptyRow := true
			for _, cell := range row.Cells {
				// Убираем XML-метки и HTML-теги
				trimmed := strings.TrimSpace(removeHTMLTags(cell.Data))
				rowData = append(rowData, trimmed)
				if trimmed != "" {
					emptyRow = false
				}
			}
			// Пропускаем строки, где все ячейки пустые
			if emptyRow {
				continue
			}

			// Если первый столбец равен "Задача", пропускаем строку как дубликат заголовка
			if len(rowData) > 0 && rowData[0] == "Задача" {
				continue
			}

			result = append(result, rowData)
		}
	}

	fmt.Printf("Обработано %d строк из %s\n", len(result), filepath.Base(filePath))
	return result
}

// Создает итоговый Excel файл
func createExcel(filename string, header []string, data [][]string) error {
	f := excelize.NewFile()
	sheet := "Sheet1"

	// Стили для оформления
	headerStyle, _ := f.NewStyle(&excelize.Style{
		Font:      &excelize.Font{Bold: true},
		Fill:      excelize.Fill{Type: "pattern", Color: []string{"#D9D9D9"}, Pattern: 1},
		Alignment: &excelize.Alignment{Horizontal: "center"},
		Border: []excelize.Border{
			{Type: "left", Color: "000000", Style: 1},
			{Type: "right", Color: "000000", Style: 1},
			{Type: "top", Color: "000000", Style: 1},
			{Type: "bottom", Color: "000000", Style: 1},
		},
	})

	cellStyle, _ := f.NewStyle(&excelize.Style{
		Border: []excelize.Border{
			{Type: "left", Color: "000000", Style: 1},
			{Type: "right", Color: "000000", Style: 1},
			{Type: "top", Color: "000000", Style: 1},
			{Type: "bottom", Color: "000000", Style: 1},
		},
	})

	// Записываем заголовки в первую строку
	f.SetSheetRow(sheet, "A1", &header)
	f.SetRowStyle(sheet, 1, 1, headerStyle)

	// Записываем данные начиная со второй строки
	for i, row := range data {
		axis, _ := excelize.CoordinatesToCellName(1, i+2)
		f.SetSheetRow(sheet, axis, &row)
		f.SetRowStyle(sheet, i+2, i+2, cellStyle)
	}

	// Настраиваем ширину столбцов
	for col := range header {
		colName, _ := excelize.ColumnNumberToName(col + 1)
		maxWidth := 0
		for _, row := range data {
			if len(row) > col && len(row[col]) > maxWidth {
				maxWidth = len(row[col])
			}
		}
		if maxWidth > 50 {
			maxWidth = 50
		}
		f.SetColWidth(sheet, colName, colName, float64(maxWidth+2))
	}

	return f.SaveAs(filename)
}
