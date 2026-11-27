# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Fixed

## [0.6.0] - 2026-11-27

### Added
- 同一種別の複数ファイル間で完全一致するログ行の重複除外と除外数表示。
- アクセス数の5分単位集計と、密な時刻軸ラベルの間引き。

## [0.5.0] - 2026-11-27

### Added
- GUIで開始・終了日時（JST）を指定し、範囲内のレコードだけをHTML/CSVへ出力。
- 期間内か判定できない時刻なしレコードの件数を画面とHTMLに表示。

## [0.4.1] - 2026-11-27

### Changed
- GC停止時間とヒープ推移の横軸もJST時刻に統一し、時刻不明イベントの件数を注記。

## [0.4.0] - 2026-11-27

### Added
- ログ種別ごとに複数ファイルを追加・削除できるGUIと、レポート出力先の選択機能。
- リクエスト数、GC停止時間、GC後ヒープの値・単位・横軸説明を備えたSVGグラフ。
### Changed
- GUIをタブと一覧中心に整理し、出力先と解析結果を分かりやすく表示。
- HTMLレポートを概要、軸ラベル付きグラフ、詳細表、注意事項で構成。

## [0.3.0] - 2026-11-27

### Added
- Windows起動用バッチファイル。子プロセス限定のExecutionPolicy Bypassで起動し、永続設定は変更しない。

## [0.2.0] - 2026-11-27

### Added
- GCViewerの分析機能を参考に、GCイベント詳細、停止時間の統計とグラフ、GC後ヒープ推移、Full GC間隔、前後ヒープ量のCSV出力を追加。
- Java 8系のGCログ、JVM統合GCログ、アプリケーション停止時間イベントの代表形式に対応。

## [0.1.1] - 2026-11-27

### Fixed
- Windows PowerShell 5.1 UTF-8 source compatibility.
- Apache Combined parsing when no response-time field exists.
- CI test for the self-contained hourly HTML chart.

## [0.1.0] - 2026-11-26

### Added
- Initial design, PowerShell GUI, Apache/JBoss/GC parsing, HTML/CSV exports, and synthetic log tests.
