import { Component, inject, signal, computed } from '@angular/core';
import { FormsModule } from '@angular/forms';
import { DatePipe } from '@angular/common';
import { AlertService, AlertFilters } from '../../core/services/alert.service';
import { CacheService } from '../../core/services/cache.service';
import { Alert, PaginatedResponse } from '../../core/models';

@Component({
  selector: 'app-alerts',
  imports: [FormsModule, DatePipe],
  templateUrl: './alerts.html',
  styleUrl: './alerts.scss'
})
export class AlertsPage {
  private svc   = inject(AlertService);
  private cache = inject(CacheService);

  // Vista por defecto: señal reactiva del cache (se actualiza en background automáticamente)
  private defaultResult = this.cache.signal<PaginatedResponse<Alert>>('alerts_default');

  // Vista con filtros: fetch manual
  private filterResult = signal<PaginatedResponse<Alert> | null>(null);
  private isFiltered   = signal(false);

  // La vista actual: usa el cache si no hay filtros, el resultado del filtro si los hay
  result  = computed(() => this.isFiltered() ? this.filterResult() : this.defaultResult());
  loading = signal(false);
  error   = signal('');
  selected = signal<Alert | null>(null);

  filters: AlertFilters = {};

  statusOptions   = ['', 'open', 'in_progress', 'resolved', 'dismissed'];
  severityOptions = ['', 'critical', 'high', 'medium', 'low'];

  applyFilters() {
    this.isFiltered.set(true);
    this.loading.set(true);
    this.error.set('');
    this.svc.list({ ...this.filters, page: 1 }).subscribe({
      next: r  => { this.filterResult.set(r); this.loading.set(false); },
      error: () => { this.error.set('Error al cargar alertas.'); this.loading.set(false); }
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

  open(alert: Alert)  { this.selected.set(alert); }
  close()             { this.selected.set(null); }

  changeStatus(alert: Alert, status: string) {
    console.log('[AlertsPage] changeStatus called', { id: alert.id, status });
    this.svc.updateStatus(alert.id, status).subscribe({
      next: updated => {
        console.log('[AlertsPage] updateStatus OK', updated);
        const r = this.result();
        if (r) {
          const updated_list = { ...r, data: r.data.map(a => a.id === updated.id ? updated : a) };
          if (this.isFiltered()) {
            this.filterResult.set(updated_list);
          } else {
            this.cache.set('alerts_default', updated_list);
          }
        }
        if (this.selected()?.id === updated.id) this.selected.set(updated);
      },
      error: (err) => {
        console.error('[AlertsPage] updateStatus FAILED', err);
        this.error.set('Error al cambiar el estado de la alerta.');
      }
    });
  }

  severityClass(name?: string) { return `badge badge-${name?.toLowerCase() ?? 'low'}`; }
  statusClass(s: string)       { return `badge badge-${s}`; }

  severityLabel(k?: string) {
    return { critical: 'Crítica', high: 'Alta', medium: 'Media', low: 'Baja' }[k ?? ''] ?? (k ?? '');
  }
  statusLabel(s: string) {
    return { open: 'Abierta', in_progress: 'En proceso', resolved: 'Resuelta', dismissed: 'Descartada' }[s] ?? s;
  }
}
