/**
 * AssetFlow Cleaner & Optimizer - Admin Scripts
 */

jQuery(document).ready(function ($) {
    'use strict';

    var scanData = null;

    // ثبت پیام در کنسول لاگ زنده
    function logMessage(text, type) {
        type = type || 'system';
        var time = new Date().toLocaleTimeString('fa-IR');
        var $terminal = $('#afc-terminal');
        var line = $('<div class="afc-terminal-line ' + type + '">[' + time + '] ' + text + '</div>');
        $terminal.append(line);
        $terminal.scrollTop($terminal[0].scrollHeight);
    }

    // تغییر زبانه‌ها
    $('.afc-tab-btn').on('click', function (e) {
        e.preventDefault();
        var targetTab = $(this).data('tab');

        $('.afc-tab-btn').removeClass('active');
        $(this).addClass('active');

        $('.afc-tab-pane').removeClass('active');
        $('#' + targetTab).addClass('active');
    });

    // شروع اسکن کامل
    $('#afc-btn-quick-scan, .afc-btn-start-scan').on('click', function (e) {
        e.preventDefault();
        startFullScan();
    });

    function startFullScan() {
        var $btn = $('#afc-btn-quick-scan');
        var $progressBox = $('#afc-progress-box');
        var $progressBar = $('#afc-progress-bar');
        var $progressMsg = $('#afc-progress-msg');

        $btn.prop('disabled', true);
        $progressBox.slideDown();
        $progressBar.css('width', '25%');
        $progressMsg.text(afcData.strings.scanning);
        logMessage('شروع اسکن عمیق سیستم و دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_scan_system',
                nonce: afcData.nonce
            },
            success: function (response) {
                $progressBar.css('width', '100%');
                setTimeout(function () {
                    $progressBox.slideUp();
                    $btn.prop('disabled', false);
                }, 600);

                if (response.success) {
                    scanData = response.data;
                    renderScanResults(scanData);
                    logMessage('اسکن با موفقیت به پایان رسید. تعداد تهدیدات یافت‌شده: ' + scanData.stats.threats_count, scanData.stats.threats_count > 0 ? 'danger' : 'success');
                } else {
                    logMessage('خطا در انجام اسکن: ' + (response.data.message || 'نامشخص'), 'danger');
                }
            },
            error: function (xhr, status, error) {
                $progressBox.slideUp();
                $btn.prop('disabled', false);
                logMessage('خطای غیرمنتظره در ارتباط AJAX: ' + error, 'danger');
            }
        });
    }

    // رندر نتایج اسکن در UI
    function renderScanResults(data) {
        $('#afc-empty-state').hide();
        $('#afc-scan-results').show();

        // به‌روزرسانی کارت‌های آماری
        var threats = data.stats.threats_count;
        var usersCount = data.hidden_users.length;
        var dbCount = data.options.length + data.tables.length;
        var filesCount = data.infected_files.length;
        var muCount = data.mu_plugins.length;

        $('#afc-val-users').text(usersCount);
        $('#afc-val-db').text(dbCount);
        $('#afc-val-files').text(filesCount);
        $('#afc-val-mu').text(muCount);

        var $statusVal = $('#afc-val-status');
        if (threats > 0) {
            $statusVal.text('آلودگی بحرانی (' + threats + ' مورد)').removeClass('afc-status-safe').addClass('afc-status-danger');
            $('#afc-btn-fix-all').fadeIn();
        } else {
            $statusVal.text('کاملاً امن و پاک').removeClass('afc-status-danger').addClass('afc-status-safe');
            $('#afc-btn-fix-all').fadeOut();
        }

        // ۱. رندر کاربران مخفی
        renderUsersSection(data.hidden_users);

        // ۲. رندر جداول و آپشن‌های دیتابیس
        renderDbSection(data.options, data.tables);

        // ۳. رندر mu-plugins
        renderMuSection(data.mu_plugins);

        // ۴. رندر فایل‌های آلوده
        renderInfectedFilesSection(data.infected_files);

        // ۵. رندر فایل‌های php در uploads
        renderUploadsSection(data.uploads_php);
    }

    function renderUsersSection(users) {
        var $badge = $('#afc-badge-users');
        var $body = $('#afc-list-users');
        $body.empty();

        if (users.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ کاربر مخفی یا درپشتی در دیتابیس شناسایی نشد.</p>');
            return;
        }

        $badge.text(users.length + ' مورد خطرناک').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>شناسه (ID)</th><th>نام کاربری</th><th>ایمیل</th><th>نقش</th><th>تاریخ ثبت</th></tr></thead><tbody>';

        users.forEach(function (u) {
            html += '<tr>' +
                '<td>' + u.ID + '</td>' +
                '<td><strong style="color:#dc2626;"><code>' + u.user_login + '</code></strong></td>' +
                '<td>' + u.user_email + '</td>' +
                '<td><span class="afc-badge afc-badge-danger">مدیر کل (Backdoor)</span></td>' +
                '<td>' + u.registered + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderDbSection(options, tables) {
        var $badge = $('#afc-badge-db');
        var $body = $('#afc-list-db');
        $body.empty();

        var total = options.length + tables.length;
        if (total === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ جدول یا آپشن مخربی در دیتابیس یافت نشد.</p>');
            return;
        }

        $badge.text(total + ' مورد آلوده').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>نوع موجودیت</th><th>نام شیء</th><th>جزئیات / مقدار</th></tr></thead><tbody>';

        options.forEach(function (o) {
            html += '<tr><td><span class="afc-badge afc-badge-warning">Option</span></td><td><code>' + o.option_name + '</code></td><td><code>' + o.value + '</code></td></tr>';
        });

        tables.forEach(function (t) {
            html += '<tr><td><span class="afc-badge afc-badge-danger">Table</span></td><td><code>' + t.table_name + '</code></td><td>' + t.row_count + ' رکورد ثبت‌شده</td></tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderMuSection(muFiles) {
        var $badge = $('#afc-badge-mu');
        var $body = $('#afc-list-mu');
        $body.empty();

        if (muFiles.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">پوشه Must-Use Plugins فاقد هرگونه فایل مشکوک است.</p>');
            return;
        }

        $badge.text(muFiles.length + ' فایل پایدار').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>نام فایل</th><th>مسیر</th><th>علت شناسایی</th></tr></thead><tbody>';

        muFiles.forEach(function (f) {
            html += '<tr>' +
                '<td><strong style="color:#dc2626;">' + f.filename + '</strong></td>' +
                '<td><code>' + f.relative + '</code></td>' +
                '<td><span class="afc-badge afc-badge-danger">' + f.reason + '</span></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderInfectedFilesSection(files) {
        var $badge = $('#afc-badge-files');
        var $body = $('#afc-list-files');
        $body.empty();

        if (files.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ فایل PHP آلوده‌ای در مسیرهای اسکن‌شده شناسایی نشد.</p>');
            return;
        }

        $badge.text(files.length + ' فایل آلوده').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>مسیر فایل</th><th>حجم</th><th>نوع تزریق و امضا</th><th>عملیات</th></tr></thead><tbody>';

        files.forEach(function (f) {
            var typeBadge = '';
            var actionBtn = '';

            if (f.is_assetflow) {
                var typeLabel = f.is_injected_bottom ? 'الحاق Asset Flow (قابل جراحی)' : 'فایل مستقل بدافزار Asset Flow';
                typeBadge = '<span class="afc-badge afc-badge-danger">' + typeLabel + '</span>';
                actionBtn = '<button class="button button-small button-primary afc-btn-repair-single" data-path="' + f.path + '">ترمیم و جراحی</button>';
            } else {
                typeBadge = '<span class="afc-badge afc-badge-warning">وب‌شل / اسکریپت مخرب (اکتشافی)</span>';
                actionBtn = '<button class="button button-small button-danger afc-btn-delete-upload-file" data-path="' + f.path + '" style="margin-left:5px;">حذف فایل</button>' +
                            '<button class="button button-small button-secondary afc-btn-repair-single" data-path="' + f.path + '">تلاش برای ترمیم</button>';
            }

            html += '<tr data-filepath="' + f.path + '">' +
                '<td><code>' + f.relative + '</code></td>' +
                '<td>' + f.size + '</td>' +
                '<td>' + typeBadge + ' <small style="display:block; color:#64748b; margin-top:4px;">' + f.signatures + '</small></td>' +
                '<td>' + actionBtn + '</td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    function renderUploadsSection(uploads) {
        var $badge = $('#afc-badge-uploads');
        var $body = $('#afc-list-uploads');
        $body.empty();

        if (!uploads || uploads.length === 0) {
            $badge.text('پاک').removeClass('afc-badge-danger').addClass('afc-badge-safe');
            $body.html('<p style="color:#16a34a; margin:0;">هیچ اسکریپت PHP غیرمجازی در پوشه Uploads وجود ندارد.</p>');
            return;
        }

        $badge.text(uploads.length + ' مورد مشکوک').removeClass('afc-badge-safe').addClass('afc-badge-danger');
        var html = '<table class="afc-table"><thead><tr><th>مسیر فایل</th><th>حجم</th><th>وضعیت</th><th>عملیات</th></tr></thead><tbody>';

        uploads.forEach(function (u) {
            html += '<tr data-filepath="' + u.path + '">' +
                '<td><code>' + u.relative + '</code></td>' +
                '<td>' + u.size + '</td>' +
                '<td><span class="afc-badge afc-badge-danger">اسکریپت PHP غیرمجاز</span></td>' +
                '<td><button class="button button-small button-link-delete afc-btn-delete-upload-file" data-path="' + u.path + '">حذف این فایل</button></td>' +
                '</tr>';
        });

        html += '</tbody></table>';
        $body.html(html);
    }

    // حذف تکی فایل از آپلودها
    $(document).on('click', '.afc-btn-delete-upload-file', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var filePath = $btn.data('path');
        var $row = $btn.closest('tr');

        if (!confirm('آیا از حذف این فایل مشکوک مطمئن هستید؟')) {
            return;
        }

        $btn.prop('disabled', true).text('در حال حذف...');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_delete_single_file',
                file_path: filePath,
                nonce: afcData.nonce
            },
            success: function (res) {
                if (res.success) {
                    $row.fadeOut(300, function () { $(this).remove(); });
                    logMessage('فایل حذف شد: ' + filePath, 'success');
                } else {
                    $btn.prop('disabled', false).text('تلاش مجدد');
                    alert(res.data.message || 'خطا در حذف فایل');
                }
            },
            error: function () {
                $btn.prop('disabled', false).text('تلاش مجدد');
                alert(afcData.strings.error_occurred);
            }
        });
    });

    // ترمیم تکی یک فایل
    $(document).on('click', '.afc-btn-repair-single', function (e) {
        e.preventDefault();
        var $btn = $(this);
        var filePath = $btn.data('path');
        var $row = $btn.closest('tr');

        $btn.prop('disabled', true).text('در حال ترمیم...');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_repair_single_file',
                file_path: filePath,
                nonce: afcData.nonce
            },
            success: function (response) {
                if (response.success) {
                    $row.css('background', '#dcfce7');
                    $btn.replaceWith('<span class="afc-badge afc-badge-safe">ترمیم شد</span>');
                    logMessage('فایل ترمیم شد: ' + filePath, 'success');
                } else {
                    $btn.prop('disabled', false).text('تلاش مجدد');
                    alert(response.data.message);
                    logMessage('خطا در ترمیم فایل: ' + filePath + ' (' + response.data.message + ')', 'danger');
                }
            },
            error: function () {
                $btn.prop('disabled', false).text('تلاش مجدد');
                alert(afcData.strings.error_occurred);
            }
        });
    });

    // پاک‌سازی دیتابیس
    $('#afc-act-clean-db').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('در حال پاک‌سازی دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_clean_database',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('دیتابیس با موفقیت پاک‌سازی شد.');
                    startFullScan();
                }
            }
        });
    });

    // پاک‌سازی mu-plugins
    $('#afc-act-clean-mu').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('در حال حذف فایل‌های mu-plugins...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_clean_mu_plugins',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('پوشه mu-plugins پاک‌سازی شد.');
                    startFullScan();
                }
            }
        });
    });

    // ترمیم همه فایل‌های آلوده
    $('#afc-act-clean-files').on('click', function (e) {
        e.preventDefault();
        if (!scanData || !scanData.infected_files || scanData.infected_files.length === 0) {
            alert('ابتدا اسکن را اجرا کنید یا فایلی برای ترمیم وجود ندارد.');
            return;
        }

        if (!confirm(afcData.strings.confirm_clean)) {
            return;
        }

        var filePaths = scanData.infected_files.map(function (f) { return f.path; });
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('شروع عملیات جراحی و ترمیم دسته‌جمعی فایل‌ها...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_repair_all_files',
                files: filePaths,
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.logs.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('تعداد ' + res.data.repaired + ' فایل ترمیم شد و ' + res.data.deleted + ' فایل مخرب حذف گردید.');
                    startFullScan();
                }
            }
        });
    });

    // پاک‌سازی uploads
    $('#afc-act-clean-uploads').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_clean_uploads_php',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('پوشه رسانه پاک‌سازی شد.');
                    startFullScan();
                }
            }
        });
    });

    // دکمه پاک‌سازی یک‌کلیکه همه موارد
    $('#afc-btn-fix-all').on('click', function (e) {
        e.preventDefault();
        if (!confirm(afcData.strings.confirm_all)) {
            return;
        }

        logMessage('>>> آغاز عملیات جامع پاک‌سازی و رفع آلودگی کلی سایت...', 'warning');

        // مرحله ۱: پاک‌سازی دیتابیس
        $.post(afcData.ajax_url, { action: 'afc_clean_database', nonce: afcData.nonce }, function () {
            logMessage('مرحله ۱: دیتابیس و کاربران مخفی پاک‌سازی شدند.', 'success');

            // مرحله ۲: پاک‌سازی mu-plugins
            $.post(afcData.ajax_url, { action: 'afc_clean_mu_plugins', nonce: afcData.nonce }, function () {
                logMessage('مرحله ۲: درپشتی‌های mu-plugins حذف شدند.', 'success');

                // مرحله ۳: پاک‌سازی آپلودها
                $.post(afcData.ajax_url, { action: 'afc_clean_uploads_php', nonce: afcData.nonce }, function () {
                    logMessage('مرحله ۳: اسکریپت‌های uploads بررسی شدند.', 'success');

                    // مرحله ۴: ترمیم فایل‌ها
                    if (scanData && scanData.infected_files && scanData.infected_files.length > 0) {
                        var filePaths = scanData.infected_files.map(function (f) { return f.path; });
                        $.post(afcData.ajax_url, { action: 'afc_repair_all_files', files: filePaths, nonce: afcData.nonce }, function (fileRes) {
                            logMessage('مرحله ۴: فایل‌های PHP با موفقیت جراحی و ترمیم شدند.', 'success');
                            alert('عملیات پاک‌سازی جامع به پایان رسید. اسکن مجدد انجام می‌شود.');
                            startFullScan();
                        });
                    } else {
                        alert('عملیات با موفقیت به پایان رسید.');
                        startFullScan();
                    }
                });
            });
        });
    });

    // بهینه‌سازی دیتابیس
    $('#afc-act-optimize-db').on('click', function (e) {
        e.preventDefault();
        var $btn = $(this);
        $btn.prop('disabled', true);
        logMessage('شروع بهینه‌سازی، دیفرگ جداول و پاک‌سازی حافظه موقت دیتابیس...', 'system');

        $.ajax({
            url: afcData.ajax_url,
            type: 'POST',
            dataType: 'json',
            data: {
                action: 'afc_optimize_database',
                nonce: afcData.nonce
            },
            success: function (res) {
                $btn.prop('disabled', false);
                if (res.success) {
                    res.data.report.log.forEach(function (l) {
                        logMessage(l, 'success');
                    });
                    alert('دیتابیس با موفقیت بهینه‌سازی شد!');
                }
            }
        });
    });

    // دریافت و کپی Salts
    $('#afc-btn-get-salts').on('click', function (e) {
        e.preventDefault();
        $.post(afcData.ajax_url, { action: 'afc_generate_salts', nonce: afcData.nonce }, function (res) {
            if (res.success) {
                $('#afc-salts-text').val(res.data.salts);
                $('#afc-salts-container').slideDown();
                logMessage('کلیدهای امنیتی تصادفی جدید تولید شدند.', 'system');
            }
        });
    });

    $('#afc-copy-salts').on('click', function (e) {
        e.preventDefault();
        var copyText = document.getElementById('afc-salts-text');
        copyText.select();
        copyText.setSelectionRange(0, 99999);
        navigator.clipboard.writeText(copyText.value);
        $(this).text('کپی شد!');
        setTimeout(function () {
            $('#afc-copy-salts').text('کپی در کلیپ‌بورد');
        }, 2000);
    });

    // پاک‌سازی کنسول لاگ
    $('#afc-btn-clear-logs').on('click', function (e) {
        e.preventDefault();
        $('#afc-terminal').empty();
        logMessage('کنسول پاک شد.', 'system');
    });

});
