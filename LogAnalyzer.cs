using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text.RegularExpressions;

public class LogAnalyzer
{
    private const double THRESHOLD_SECONDS = 1.0;
    private readonly string _logFilePath;
    private readonly string _outputFilePath;

    public class LogEntry
    {
        public int LineNumber { get; set; }
        public string TimeStamp { get; set; }
        public string Level { get; set; }
        public string Component { get; set; }
        public string IPAddress { get; set; }
        public string Message { get; set; }
    }

    public class DeviationReport
    {
        public int CmdLineNumber { get; set; }
        public int RspLineNumber { get; set; }
        public string TimeStampCmd { get; set; }
        public string TimeStampRsp { get; set; }
        public string Command { get; set; }
        public double DeviationSeconds { get; set; }
        public string FullCmdLine { get; set; }
        public string FullRspLine { get; set; }
    }

    public LogAnalyzer(string logFilePath)
    {
        _logFilePath = logFilePath;
        _outputFilePath = Path.Combine(
            Path.GetDirectoryName(logFilePath),
            $"{Path.GetFileNameWithoutExtension(logFilePath)}_REPORT.txt"
        );
    }

    public void Analyze()
    {
        Console.WriteLine($"Analizzando file: {_logFilePath}");
        Console.WriteLine($"Soglia: {THRESHOLD_SECONDS} secondi");
        Console.WriteLine("---");

        var deviations = new List<DeviationReport>();

        try
        {
            using (var reader = new StreamReader(_logFilePath))
            {
                string line;
                int lineNumber = 0;
                LogEntry previousEntry = null;

                while ((line = reader.ReadLine()) != null)
                {
                    lineNumber++;
                    var entry = ParseLogLine(line, lineNumber);

                    if (entry != null)
                    {
                        // Controlla se la linea precedente era un CMD (lg o lr) e questa è RSP
                        if (previousEntry != null &&
                            previousEntry.Message.StartsWith("CMD:") &&
                            entry.Message.StartsWith("RSP:") &&
                            (previousEntry.Message.Contains("CMD: lg") || previousEntry.Message.Contains("CMD: lr")))
                        {
                            var deviation = CalculateDeviation(previousEntry, entry, line);
                            if (deviation != null && deviation.DeviationSeconds > THRESHOLD_SECONDS)
                            {
                                deviations.Add(deviation);
                                Console.WriteLine($"⚠️  SCOSTAMENTO RILEVATO: {deviation.DeviationSeconds:F3}s");
                                Console.WriteLine($"   Linea {deviation.CmdLineNumber}: {deviation.TimeStampCmd} {deviation.Command}");
                                Console.WriteLine($"   Linea {deviation.RspLineNumber}: {deviation.TimeStampRsp}");
                                Console.WriteLine();
                            }
                        }

                        previousEntry = entry;
                    }
                }
            }

            // Generare report
            GenerateReport(deviations);
            Console.WriteLine($"✓ Analisi completata. Scostamenti trovati: {deviations.Count}");
            Console.WriteLine($"✓ Report salvato in: {_outputFilePath}");
        }
        catch (Exception ex)
        {
            Console.WriteLine($"✗ Errore durante l'analisi: {ex.Message}");
        }
    }

    private LogEntry ParseLogLine(string line, int lineNumber)
    {
        try
        {
            // Formato: HH:MM:SS.mmm|Level|Component|IPAddress|Message
            var pattern = @"^(\d{2}:\d{2}:\d{2}\.\d{3})\|(\w+)\|(\w+)\|([0-9\.\@\-]+)\s*\|(.*)$";
            var match = Regex.Match(line, pattern);

            if (match.Success)
            {
                return new LogEntry
                {
                    LineNumber = lineNumber,
                    TimeStamp = match.Groups[1].Value,
                    Level = match.Groups[2].Value,
                    Component = match.Groups[3].Value,
                    IPAddress = match.Groups[4].Value,
                    Message = match.Groups[5].Value
                };
            }
        }
        catch
        {
            // Ignora righe malformate
        }

        return null;
    }

    private DeviationReport CalculateDeviation(LogEntry cmdEntry, LogEntry rspEntry, string fullRspLine)
    {
        try
        {
            var cmdTime = TimeSpan.Parse(cmdEntry.TimeStamp);
            var rspTime = TimeSpan.Parse(rspEntry.TimeStamp);

            double deviationSeconds = (rspTime - cmdTime).TotalSeconds;

            // Gestisce il caso di cambio ora (es. 23:59:59 -> 00:00:01)
            if (deviationSeconds < 0)
            {
                deviationSeconds += 24 * 3600; // Aggiungi 24 ore
            }

            // Estrai il comando (lg o lr)
            var cmdMatch = Regex.Match(cmdEntry.Message, @"CMD:\s*(lg|lr)\d+");
            var command = cmdMatch.Success ? cmdMatch.Groups[1].Value : "unknown";

            return new DeviationReport
            {
                CmdLineNumber = cmdEntry.LineNumber,
                RspLineNumber = rspEntry.LineNumber,
                TimeStampCmd = cmdEntry.TimeStamp,
                TimeStampRsp = rspEntry.TimeStamp,
                Command = command,
                DeviationSeconds = deviationSeconds,
                FullCmdLine = $"{cmdEntry.TimeStamp}|{cmdEntry.Message}",
                FullRspLine = fullRspLine.Trim()
            };
        }
        catch
        {
            return null;
        }
    }

    private void GenerateReport(List<DeviationReport> deviations)
    {
        using (var writer = new StreamWriter(_outputFilePath, false, System.Text.Encoding.UTF8))
        {
            writer.WriteLine("╔════════════════════════════════════════════════════════════════════════╗");
            writer.WriteLine("║         REPORT ANALISI LOG - SCOSTAMENTI TEMPORALI                    ║");
            writer.WriteLine("╚════════════════════════════════════════════════════════════════════════╝");
            writer.WriteLine();
            writer.WriteLine($"File analizzato: {Path.GetFileName(_logFilePath)}");
            writer.WriteLine($"Data analisi: {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
            writer.WriteLine($"Soglia scostamento: {THRESHOLD_SECONDS} secondi");
            writer.WriteLine($"Scostamenti rilevati: {deviations.Count}");
            writer.WriteLine();
            writer.WriteLine("═" + new string('═', 73));
            writer.WriteLine();

            if (deviations.Count == 0)
            {
                writer.WriteLine("✓ Nessuno scostamento rilevato superiore a {0}s", THRESHOLD_SECONDS);
            }
            else
            {
                // Statistiche
                var avgDeviation = deviations.Average(d => d.DeviationSeconds);
                var maxDeviation = deviations.Max(d => d.DeviationSeconds);
                var minDeviation = deviations.Min(d => d.DeviationSeconds);

                writer.WriteLine("STATISTICHE:");
                writer.WriteLine($"  - Scostamento minimo: {minDeviation:F3}s");
                writer.WriteLine($"  - Scostamento massimo: {maxDeviation:F3}s");
                writer.WriteLine($"  - Scostamento medio:   {avgDeviation:F3}s");
                writer.WriteLine();
                writer.WriteLine("─" + new string('─', 73));
                writer.WriteLine();

                // Dettagli scostamenti ordinati per valore decrescente
                var sortedDeviations = deviations.OrderByDescending(d => d.DeviationSeconds).ToList();

                for (int i = 0; i < sortedDeviations.Count; i++)
                {
                    var dev = sortedDeviations[i];
                    writer.WriteLine($"SCOSTAMENTO #{i + 1} - {dev.DeviationSeconds:F3}s (Superiore di {dev.DeviationSeconds - THRESHOLD_SECONDS:F3}s)");
                    writer.WriteLine($"  Comando: {dev.Command.ToUpper()}");
                    writer.WriteLine($"  Linea {dev.CmdLineNumber}: [{dev.TimeStampCmd}] {dev.FullCmdLine}");
                    writer.WriteLine($"  Linea {dev.RspLineNumber}: [{dev.TimeStampRsp}] {dev.FullRspLine}");
                    writer.WriteLine();
                }

                // Riepilogo per tipo di comando
                writer.WriteLine("─" + new string('─', 73));
                writer.WriteLine();
                writer.WriteLine("RIEPILOGO PER TIPO DI COMANDO:");

                var groupedByCmd = deviations.GroupBy(d => d.Command).ToList();
                foreach (var group in groupedByCmd)
                {
                    writer.WriteLine($"  • Comando '{group.Key.ToUpper()}': {group.Count()} scostamenti");
                    var avgCmd = group.Average(d => d.DeviationSeconds);
                    var maxCmd = group.Max(d => d.DeviationSeconds);
                    writer.WriteLine($"    - Media: {avgCmd:F3}s | Massimo: {maxCmd:F3}s");
                }
            }

            writer.WriteLine();
            writer.WriteLine("═" + new string('═', 73));
            writer.WriteLine($"Fine report - {DateTime.Now:yyyy-MM-dd HH:mm:ss}");
        }
    }

    public static void Main(string[] args)
    {
        if (args.Length == 0)
        {
            Console.WriteLine("Utilizzo: LogAnalyzer <percorso_file_log>");
            Console.WriteLine();
            Console.WriteLine("Esempio:");
            Console.WriteLine("  LogAnalyzer \"C:\\logs\\P2LightMaster_192.168.70.249_log20260430.txt\"");
            return;
        }

        string logFile = args[0];

        if (!File.Exists(logFile))
        {
            Console.WriteLine($"✗ File non trovato: {logFile}");
            return;
        }

        var analyzer = new LogAnalyzer(logFile);
        analyzer.Analyze();
    }
}
