# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
### Changed
### Fixed

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
