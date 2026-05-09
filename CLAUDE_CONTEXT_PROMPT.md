# Контекстный промпт для Claude - Диссертация по Web Security Analysis

## ОБЩИЙ КОНТЕКСТ ПРОЕКТА

### Название работы
**"Development of an Interactive AI-Assisted System for Web Vulnerability Analysis and Threat Reporting"**

или на русском:
**"Разработка интерактивной AI-ассистированной системы анализа веб-уязвимостей и формирования отчетов об угрозах"**

---

## 1. СУТЬ ПРОЕКТА И ИССЛЕДОВАТЕЛЬСКАЯ ЗАДАЧА

Проект представляет собой **дипломную работу** по специальности **Кибербезопасность** (6B06301) в Astana IT University.

### Основная проблема исследования
Традиционные инструменты статического (SAST) и динамического (DAST) анализа неэффективны против современных киберугроз, особенно в контексте:
- Быстрого роста AI-ассистированных атак
- Необходимости снижения времени реакции Security Operations Center (SOC)
- Высокого уровня ложноположительных срабатываний в традиционных сканерах

### Цель работы
Разработать и оценить **интерактивную AI-ассистированную систему анализа веб-уязвимостей**, которая:
1. Объединяет автоматизированное сканирование с LLM-ориентированным анализом
2. Уменьшает время реагирования аналитика
3. Повышает доверие аналитиков к результатам
4. Применяет принцип Human-in-the-Loop (HITL)

---

## 2. АРХИТЕКТУРА СИСТЕМЫ

### Технологический стек
```
Backend:        Python Flask
ORM:            SQLAlchemy
Database:       SQLite (instance/scan_history.db)
Frontend:       HTML / CSS / JavaScript
AI Model:       Google Gemini 2.5 Flash
API:            Shodan API для reconnaissance
Deployment:     Docker + Docker Compose
```

### Основные компоненты системы

#### A. Модуль сканирования портов
- **Технология**: Python `socket` + `concurrent.futures.ThreadPoolExecutor`
- **Функциональность**: 
  - Параллельное сканирование TCP-портов (100 worker threads)
  - Timeout 500ms для каждого соединения
  - Преобразование домена в IP адрес
  - Сохранение истории сканирования в БД

#### B. Модуль анализа HTTP-заголовков
- **Технология**: Python `requests`
- **Функциональность**:
  - Извлечение HTTP headers из ответа сервера
  - Анализ наличия/отсутствия security headers:
    - Content-Security-Policy (CSP)
    - X-Frame-Options
    - Strict-Transport-Security
    - X-Content-Type-Options
  - Выявление информативных заголовков (Server, X-Powered-By)

#### C. Модуль поиска скриптов
- **Технология**: Python `re` (регулярные выражения)
- **Функциональность**:
  - Парсинг HTML страницы
  - Поиск ссылок на `.js` файлы (JavaScript)
  - Поиск ссылок на `.cgi` скрипты
  - Дедупликация результатов

#### D. Модуль Shodan reconnaissance
- **Технология**: Shodan Python API
- **Функциональность**:
  - Пассивный сбор информации о хосте
  - IP адрес, организация, OS, страна, город, координаты
  - Список открытых портов по данным Shodan
  - Обогащение результатов активного сканирования

#### E. AI-модуль отчетности
- **Модель**: Google Gemini 2.5 Flash
- **Функциональность**:
  - Human-in-the-Loop (HITL) архитектура
  - Получает агрегированные данные сканирования
  - Анализирует угрозы в контексте кибербезопасности
  - Выводит:
    - Уровень угрозы (Low/Medium/High)
    - Риски открытых портов
    - Пропущенные security headers
    - Рекомендации по исправлению
  - Возвращает ответ в Markdown формате

#### F. Интерфейс пользователя
- **Стек**: HTML/CSS/JavaScript
- **Функциональность**:
  - Форма для ввода целевого домена и диапазона портов
  - Динамическое отображение результатов сканирования
  - Интерактивная панель отчетности AI
  - История сканирований
  - Переключение тем (светлая/темная)
  - Асинхронные запросы (Fetch API) к бэкенду

#### G. Хранилище истории
- **Технология**: SQLite + SQLAlchemy ORM
- **Таблица**: `ScanHistory`
  - `id` (Primary Key)
  - `domain` (VARCHAR 255, NOT NULL)
  - `start_port` (INTEGER, nullable)
  - `end_port` (INTEGER, nullable)
  - `action` (VARCHAR 50, NOT NULL)
  - `timestamp` (DATETIME, default UTC)

---

## 3. КЛЮЧЕВЫЕ МЕТРИКИ И РЕЗУЛЬТАТЫ

### Результаты оценки на OWASP Benchmark v1.2

| Метрика | Значение |
|---------|----------|
| **F1-Score** | 88.0% |
| **Precision** | 91.0% |
| **Recall** | 85.0% |
| **False Positive Rate (FPR)** | 4.1% |

### Сравнение с baseline системами

| Система | F1-Score | FPR |
|---------|----------|-----|
| Traditional SAST (CodeQL) | 74.4% | 68.2% |
| Traditional DAST (OWASP ZAP) | 57.0% | 12.2% |
| Monolithic LLM (GPT-4o) | 75.0% | 28.4% |
| **Proposed System** | **88.0%** | **4.1%** |

### Операционная эффективность

| Метрика | Значение |
|---------|----------|
| **MTTT (Mean Time to Triage)** | 4.8 минут (vs 35 мин вручную, -86%) |
| **Report Generation Time** | 3.5 минут |
| **Analyst Trust Rating** | 9.1/10 |

---

## 4. КРИТИЧЕСКИЕ АСПЕКТЫ ИССЛЕДОВАНИЯ

### A. Проблемы традиционных подходов (addressed в работе)

1. **CodeQL (SAST)**
   - Высокий Recall (97%) но очень высокий FPR (68.2%)
   - Не понимает бизнес-логику и custom sanitization
   - Избыточная обработка результатов аналитиком

2. **OWASP ZAP (DAST)**
   - Низкий Recall (45%) из-за:
     - Проблем с аутентификацией
     - Асинхронным DOM rendering
     - Сложными stateful взаимодействиями

3. **Standalone LLM (GPT-4o)**
   - FPR 28.4% из-за "semantic trap"
   - Халлюцинации о уязвимостях
   - Отсутствие прозрачности в рассуждениях
   - Низкое доверие аналитиков (4.2/10)

### B. Как система решает эти проблемы

1. **Dual-agent validation mechanism**
   - Detector sub-agent: высокая полнота (recall)
   - Validator sub-agent: кросс-проверка против CWE памяти
   - Dynamic interrupt при неуверенности -> человеческое решение

2. **HITL архитектура**
   - Человек инициирует сканирование
   - Человек запрашивает AI отчет вручную
   - Человек имеет доступ к raw data для проверки
   - Система pauses на точках принятия решений

3. **Прозрачность и интерпретируемость**
   - Raw telemetry всегда видна аналитику
   - AI reasoning можно cross-reference
   - Analyst может override выводы

---

## 5. СТРУКТУРА ДИССЕРТАЦИИ

### Части работы
1. **Abstract** - краткое резюме
2. **Introduction** - постановка проблемы и цели
3. **Chapter 1 (или Section 2)** - Theoretical part:
   - Literature Review
   - OWASP Top 10 analysis
   - Сравнение инструментов
   - Концепции и определения

4. **Chapter 2 (или Section 3)** - Practical part:
   - Архитектура системы
   - Методология оценки
   - Реализация компонентов
   - Результаты эмпирической оценки

5. **Chapter 3 (или Section 4)** - Results & Discussion:
   - Интерпретация результатов
   - Сравнение с baseline
   - Ограничения системы
   - Future work

6. **Conclusion** - выводы и рекомендации
7. **References** - список литературы (IEEE format)

---

## 6. СИСТЕМНЫЕ ПРОМПТЫ ДЛЯ LLM

### Текущий промпт для Gemini (в app.py)

```text
You are a professional cybersecurity expert (pentester).
Analyze the scan results for the domain: {domain}.

TECHNICAL DATA:
1. Open ports: {ports}
2. HTTP headers: {list(headers.keys())}
3. Shodan data: OS: {shodan_data.get('Operating System')}, 
                Country: {shodan_data.get('Country')}, 
                Shodan ports: {shodan_data.get('Open Ports')}
4. Website scripts: found {len(scripts.get('js_scripts', []))} JavaScript files.

YOUR TASK:
1. Assess the threat level (Low/Medium/High).
2. Explain the risks of open ports (especially dangerous ones like 21, 23, 3389).
3. Check for important security headers (X-Frame-Options, CSP). 
   If they are missing from the list, mention that as a weakness.
4. Give brief remediation recommendations.

Respond only in English. Use Markdown for clear formatting.
```

**Модель**: `gemini-2.5-flash`  
**Invocation**: `model.generate_content(prompt)`  
**Output format**: Markdown

---

## 7. РАЗВЕРТЫВАНИЕ И ЗАПУСК

### Локальный запуск
```bash
python3 app.py
# Доступна по http://127.0.0.1:5000
```

### Docker Compose (РЕКОМЕНДУЕТСЯ)
```bash
docker-compose up --build
# Доступна по http://localhost:5000
```

**Важно**: Система развертывается одной командой `docker-compose up`, что упоминается в диссертации как преимущество.

### Требуемые environment переменные
```
SHODAN_API_KEY=<your-key>
GEMINI_API_KEY=<your-key>
```

---

## 8. КЛЮЧЕВЫЕ ЦИТАТЫ И ОПРЕДЕЛЕНИЯ

### Vulnerability (NIST SP 800-30)
> A weakness in an information system, system security procedures, internal controls, or implementation that can be exploited or triggered by a threat actor.

### Threat
> Any circumstance or event that has the potential to adversely affect an organization's operations through unauthorized access, destruction, disclosure, modification of information, and/or denial of service.

### OWASP Top 10 (2021)
Основные категории уязвимостей:
- A01: Broken Access Control
- A02: Cryptographic Failures
- A03: Injection (SQLi, XSS)
- A04: Insecure Design
- A05: Security Misconfiguration
- A06: Vulnerable and Outdated Components
- A07: Identification and Authentication Failures
- A08: Software and Data Integrity Failures
- A09: Logging and Monitoring Failures
- A10: Server-Side Request Forgery (SSRF)

---

## 9. РЕКОМЕНДАЦИИ ПО ИСПОЛЬЗОВАНИЮ CLAUDE

Используйте эту информацию когда Claude просит помощь с:

1. **Улучшением диссертации**
   - Переформулировка текста в академический стиль
   - Добавление недостающих деталей
   - Гармонизация с научным контекстом

2. **Редактированием секций**
   - Literature Review: добавление источников
   - Methodology: уточнение описания
   - Results: лучшее представление данных
   - Discussion: интерпретация результатов

3. **Улучшением структуры**
   - Логичность изложения
   - Cross-references между секциями
   - Четкость формулировок

4. **Добавлением контента**
   - Больше примеров
   - Детальные объяснения алгоритмов
   - Таблицы и диаграммы

5. **Проверкой качества**
   - Грамматика и пунктуация
   - Конкретность вместо обобщений
   - Удаление LLM-стиля (вводные фразы "It's important to note...")

---

## 10. ТЕКУЩЕЕ СОСТОЯНИЕ ДОКУМЕНТОВ

### Основные файлы
- **diploma_work.md** - оригинальная дипломная работа (1867 строк)
- **статья от claude.md** - расширенная версия с AI-ориентированным фокусом (416 строк)
- **latex.md** - версия для Overleaf (819 строк)

### Что нужно улучшить
1. Упоминание Docker (`docker-compose up`)
2. Таблица с точными промптами для LLM
3. Оценка диссертации по критериям
4. Гармонизация стиля (убрать LLM-речь)
5. Переработка Literature Review

---

## 11. ИНСТРУКЦИИ ДЛЯ CLAUDE

Когда работаете над диссертацией:

### ✅ ДЕЛАЙТЕ
- Используйте формальный академический язык
- Цитируйте источники (IEEE format)
- Добавляйте конкретные примеры из кода
- Объясняйте WHY, а не просто WHAT
- Связывайте теорию и практику
- Используйте таблицы для сравнений
- Ссылайтесь на Figure/Table номера

### ❌ НЕ ДЕЛАЙТЕ
- "It's important to note that..."
- "Interestingly, ..."
- Общие фразы без конкретики
- Повторяющийся текст
- Только перечисления без объяснений
- "Let me explain..." / "Let's consider..."

### 🎯 ФОКУС
Диссертация должна показать:
1. **Понимание проблемы** - почему это актуально
2. **Знание SOTA** - что уже сделано
3. **Оригинальный вклад** - что нового в вашей системе
4. **Строгую оценку** - metrics и comparison
5. **Честные выводы** - что работает, что не работает

---

## 12. ПРИМЕРЫ ФОРМАТИРОВАНИЯ

### Таблица с результатами
```markdown
**Table I: Detection Efficacy Comparison**

| System | F1-Score | FPR | Key Advantage |
|--------|----------|-----|---|
| CodeQL | 74.4% | 68.2% | High Recall |
| OWASP ZAP | 57.0% | 12.2% | Low FPR |
| GPT-4o | 75.0% | 28.4% | Semantic reasoning |
| **Proposed** | **88.0%** | **4.1%** | HITL architecture |
```

### Цитирование
```markdown
As documented in the literature [1], AI-assisted security analysis 
has shown promising results in reducing alert fatigue [2]. 
The OWASP Benchmark v1.2 provides a standardized evaluation 
framework for this assessment [3].
```

### Математические формулы
```markdown
**F1-Score** is computed as:
$$F1 = 2 \times \frac{\text{Precision} \times \text{Recall}}{\text{Precision} + \text{Recall}}$$

where Precision = TP / (TP + FP) and Recall = TP / (TP + FN).
```

---

## РЕЗЮМЕ

Это полный контекст вашей диссертации. Claude теперь знает:
✅ Суть и цели проекта
✅ Архитектуру всех компонентов
✅ Результаты эмпирической оценки
✅ Сравнение с baseline системами
✅ Критические аспекты исследования
✅ Требуемый стиль и форматирование
✅ Что улучшить в текущих документах

**Используйте этот файл как reference при работе с Claude над диссертацией.**

---

**Дата создания**: 2026-05-06  
**Версия**: 1.0  
**Язык**: Русский + Английский (для промптов)

