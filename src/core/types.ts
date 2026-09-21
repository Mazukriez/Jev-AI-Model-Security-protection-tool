export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'info';

export type Finding = {
  id: string;
  severity: Severity;
  title: string;
  detail: string;
  field?: 'state' | 'question' | 'request';
  detector: string;
};

export type ScanInput = {
  state: string;
  question: string;
};

export type Decision = 'ALLOW' | 'REVIEW' | 'BLOCK';

export type Detector = (input: ScanInput) => Finding[];
