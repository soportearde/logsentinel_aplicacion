import { Component, inject, signal, computed, OnInit } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe, JsonPipe } from '@angular/common';
import { LogService, LogFilters } from '../../core/services/log.service';
import { CacheService } from '../../core/services/cache.service';
import { RawLog, PaginatedResponse } from '../../core/models';
import { takeUntilDestroyed } from '@angular/core/rxjs-interop';

@Component({
  selector: 'app-logs',
  imports: [FormsModule, DatePipe, JsonPipe],
  templateUrl: './logs.html',
  styleUrl: './logs.scss'
})
export class LogsPage implements OnInit {
  private svc   = inject(LogService);
  private cache = inject(CacheService);

  // Vista por defecto: señal reactiva del cache (se actualiza en background automáticamente)
  private defaultResult = this.cache.signal<PaginatedResponse<RawLog>>('logs_default');

  ngOnInit() {
    // Cargar datos solo si no existen en caché
    if (!this.defaultResult()) {
      this.loading.set(true);
      this.svc.list({ page: 1 }).pipe(
        takeUntilDestroyed()
      ).subscribe({
        next: (data) => {
          this.cache.set('logs_default', data);
          this.loading.set(false);
        },
        error: () => {
          this.error.set('Error al cargar logs.');
          this.loading.set(false);
        }
      });
    }
  }

  // Vista con filtros: fetch manual
  private filterResult = signal<PaginatedResponse<RawLog> | null>(null);
  private isFiltered   = signal(false);

  result   = computed(() => this.isFiltered() ? this.filterResult() : this.defaultResult());
  loading  = signal(false);
  error    = signal('');
  selected = signal<RawLog | null>(null);

  filters: LogFilters = {};

  applyFilters() {
    this.isFiltered.set(true);
    this.loading.set(true);
    this.error.set('');
    this.svc.list({ ...this.filters, page: 1 }).subscribe({
      next: r  => { this.filterResult.set(r); this.loading.set(false); },
      error: () => { this.error.set('Error al cargar logs.'); this.loading.set(false); }
    });
  }

  resetFilters() {
    this.filters = {};
    this.isFiltered.set(false);
    this.filterResult.set(null);
    this.error.set('');
  }

  goTo(page: number) {
    this.loading.set(true);
    const params = this.isFiltered() ? { ...this.filters, page } : { page };
    this.svc.list(params).subscribe({
      next: r  => { this.filterResult.set(r); this.isFiltered.set(true); this.loading.set(false); },
      error: () => { this.loading.set(false); }
    });
  }

  open(log: RawLog) { this.selected.set(log); }
  close()           { this.selected.set(null); }
}
